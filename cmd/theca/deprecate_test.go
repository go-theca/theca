package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// Each secret file flag warns on stderr, naming its --X-from replacement, and
// still works; the warning comes from cobra (MarkDeprecated), which also hides
// the flag from the help.
func TestFileFlagsWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	pw := secretFile(t, dir, "pw", "x", 0o600)
	if r := run(nil, "create", path, "--size", "64K", "--password-file", pw); r.e != nil {
		t.Fatal(r.e)
	}
	for _, tc := range []struct{ flag, from string }{
		{"--password-file", "--password-from"},
		{"--recovery-file", "--recovery-from"},
	} {
		r := run(nil, "info", path, "--password-file", pw, tc.flag, pw)
		want := "Flag " + tc.flag + " is deprecated: a secret file beside the container's other factors defeats them; use " + tc.from + " with keychain:, secretservice: or keepassxc:\n"
		if !strings.Contains(r.err, want) || strings.Contains(r.out, "deprecated") {
			t.Errorf("%s: stderr %q stdout %q", tc.flag, r.err, r.out)
		}
	}
	// pin-file is a flag of the key commands.
	r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pw)
	if !strings.Contains(r.err, "Flag --pin-file is deprecated: ") || !strings.Contains(r.err, "use --pin-from with") {
		t.Errorf("--pin-file: stderr %q", r.err)
	}
	// The flag still works: a container made with it opens with it.
	if r := run(nil, "info", path, "--password-file", pw); r.e != nil {
		t.Errorf("deprecated flag no longer works: %v", r.e)
	}
}

func TestFileFlagsHiddenFromHelp(t *testing.T) {
	var out bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"info", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"--password-file", "--recovery-file"} {
		if strings.Contains(out.String(), f) {
			t.Errorf("%s is listed in the help", f)
		}
	}
	if !strings.Contains(out.String(), "--password-from") {
		t.Error("--password-from is missing from the help")
	}
}

// A file: reference in a --X-from flag warns, naming the flag; a manager
// reference and a malformed one do not (the malformed one is refused later).
func TestFromFileReferenceWarns(t *testing.T) {
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "x", 0o600)
	manager(t, map[string]string{"file:" + pw: "x", "keychain:a/b": "x"})
	for _, name := range []string{"password", "recovery", "pin"} {
		var out bytes.Buffer
		cmd := RootCmd()
		cmd.SetErr(&out)
		var s secrets
		if _, ok, err := s.source(cmd, name, "", "file:"+pw); !ok || err != nil {
			t.Fatal(ok, err)
		}
		want := "Flag --" + name + "-from: a file: reference is deprecated, use keychain:, secretservice: or keepassxc:\n"
		if out.String() != want {
			t.Errorf("%s: stderr %q, want %q", name, out.String(), want)
		}
	}
	for _, ref := range []string{"keychain:a/b", "nonsense"} {
		var out bytes.Buffer
		cmd := RootCmd()
		cmd.SetErr(&out)
		var s secrets
		s.source(cmd, "password", "", ref)
		if out.Len() != 0 {
			t.Errorf("%s: unexpected warning %q", ref, out.String())
		}
	}
}

// --tpm-auth-from now refuses a file: reference, as its two siblings do.
func TestTPMAuthFromRefusesFile(t *testing.T) {
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "x", 0o600)
	r := run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm", "--tpm-auth-from", "file:"+pw)
	if r.e == nil || r.e.Error() != "--tpm-auth-from: a file: reference is refused, use keychain:, secretservice: or keepassxc:" {
		t.Errorf("got %v", r.e)
	}
}
