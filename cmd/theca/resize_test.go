package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
)

func TestJournalResize(t *testing.T) {
	dir, path, pw, _ := newContainer(t)
	data := make([]byte, 200000)
	rand.Read(data)
	if r := run(data, "import", path, "--password-file", pw, "--offset", "5000"); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "it's new.theca")
	r := run(nil, "journal", "resize", path, "--out", out, "--entries", "300", "--password-file", pw)
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	for _, want := range []string{"ok: ", "-> 300 entries", "256 sectors", "verified through the copy", "nothing was swapped",
		"mv " + shellQuote(path) + " " + shellQuote(path+".old"), "mv '" + dir + "/it'\\''s new.theca' " + shellQuote(path)} {
		if !strings.Contains(r.out, want) {
			t.Errorf("output lacks %q:\n%s", want, r.out)
		}
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("FILE was rewritten")
	}
	if r := run(nil, "info", out, "--password-file", pw); r.e != nil || !strings.Contains(r.out, "300") {
		t.Fatalf("info of the copy: %v %q", r.e, r.out)
	}
	if r := run(nil, "verify", out, "--password-file", pw); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	a := run(nil, "export", path, "--password-file", pw)
	b := run(nil, "export", out, "--password-file", pw)
	if a.e != nil || b.e != nil || a.out != b.out || a.out[5000:205000] != string(data) {
		t.Fatalf("exports differ: %v %v", a.e, b.e)
	}

	// An existing NEW is refused and left alone.
	copyBefore, _ := os.ReadFile(out)
	if r := run(nil, "journal", "resize", path, "--out", out, "--entries", "310", "--password-file", pw); !errors.Is(r.e, os.ErrExist) {
		t.Fatalf("an existing --out: %v", r.e)
	}
	if now, _ := os.ReadFile(out); !bytes.Equal(now, copyBefore) {
		t.Fatal("an existing --out was touched")
	}
}

func TestJournalResizeRefusals(t *testing.T) {
	dir, path, pw, _ := newContainer(t)
	out := filepath.Join(dir, "new.theca")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no --out":                {[]string{"journal", "resize", path, "--password-file", pw}, "--out"},
		"out is FILE":             {[]string{"journal", "resize", path, "--out", path, "--password-file", pw}, "FILE itself"},
		"no such FILE":            {[]string{"journal", "resize", filepath.Join(dir, "none"), "--out", out, "--password-file", pw}, "no such file"},
		"bad passwords":           {[]string{"journal", "resize", path, "--out", out, "--entries", "300", "--password-file", secretFile(t, dir, "bad", "no\n", 0o600)}, ""},
		"missing pw":              {[]string{"journal", "resize", path, "--out", out, "--password-file", filepath.Join(dir, "none")}, "no such file"},
		"out in a gone directory": {[]string{"journal", "resize", path, "--out", filepath.Join(dir, "gone", "x"), "--entries", "300", "--password-file", pw}, "no such file"},
		"counter flag error":      {[]string{"journal", "resize", path, "--out", out, "--counter", "sgx", "--password-file", pw}, "want tpm"},
	} {
		r := run(nil, tc.args...)
		if r.e == nil || !strings.Contains(r.e.Error(), tc.want) {
			t.Errorf("%s: %v", name, r.e)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: a NEW was left behind", name)
		}
	}
	// The default size of this volume: a no-op is refused, and leaves no file.
	r := run(nil, "journal", "resize", path, "--out", out, "--password-file", pw)
	if !errors.Is(r.e, theca.ErrResizeSame) {
		t.Fatalf("a resize to the same size: %v", r.e)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused resize left its --out behind")
	}
}

func TestJournalResizeWithCounter(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	auth := secretFile(t, dir, "auth", "index secret\n", 0o600)
	owner := secretFile(t, dir, "owner", "owner secret\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	if r := run(nil, "create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm",
		"--tpm-handle", "0x01500042", "--tpm-auth-file", auth, "--tpm-owner-auth-file", owner); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	flags := []string{"--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth}
	out := filepath.Join(dir, "new.theca")

	// Without the counter flag the refusal names it, and no NEW is left.
	if r := run(nil, "journal", "resize", path, "--out", out, "--entries", "300", "--password-file", pw); !errors.Is(r.e, theca.ErrCounter) || !strings.Contains(r.e.Error(), "--counter tpm") {
		t.Fatalf("without the counter: %v", r.e)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a NEW was left behind")
	}

	v := f.ctr.v
	r := run(nil, append([]string{"journal", "resize", path, "--out", out, "--entries", "300"}, flags...)...)
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	if f.ctr.v != v+1 {
		t.Fatalf("the resize moved the counter from %d to %d, once was expected", v, f.ctr.v)
	}
	// The copy is accepted; the old file is refused from then on.
	if r := run(nil, append([]string{"verify", out}, flags...)...); r.e != nil {
		t.Fatalf("the copy: %v %s", r.e, r.err)
	}
	if r := run(nil, append([]string{"verify", path}, flags...)...); !errors.Is(r.e, theca.ErrRollback) {
		t.Fatalf("the old file after the copy was mounted: %v", r.e)
	}
}
