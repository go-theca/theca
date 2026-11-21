package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
)

// go-theca/theca#66. A container that gained its rollback counter AFTER it was
// created (`counter rebind` on a container with none) keeps, in every copy made
// before that, a header that names no counter. The master secret never rotates,
// so that copy still authenticates. Restored over the current file, it must
// not open under `--counter tpm`: asking for the counter means requiring it.
func TestCounterAskedButHeaderNamesNone(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")

	if r := run(nil, "create", path, "--size", "1M", "--password-file", pw); r.e != nil {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Control: with no counter asked, a container with none still opens.
	if r := run(nil, "info", path, "--password-file", pw); r.e != nil || !strings.Contains(r.err, "no rollback counter") {
		t.Fatalf("control: a container with no counter, none asked: %v %q", r.e, r.err)
	}

	// The owner adopts the counter.
	if r := run(nil, "counter", "rebind", path, "--counter", "tpm", "--password-file", pw); r.e != nil {
		t.Fatalf("rebind: %v %q", r.e, r.err)
	}
	r := run(nil, "info", path, "--counter", "tpm", "--password-file", pw)
	if r.e != nil || !strings.Contains(r.out, "rollback protected: true") {
		t.Fatalf("control: the rebound container is not protected: %v %q %q", r.e, r.out, r.err)
	}
	// Control: an ordinary rollback (a copy taken while bound) IS refused.
	bound, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := run(nil, "info", path, "--counter", "tpm", "--password-file", pw); r.e != nil {
		t.Fatalf("second mount: %v %q", r.e, r.err)
	}
	if err := os.WriteFile(path, bound, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, "info", path, "--counter", "tpm", "--password-file", pw); !errors.Is(r.e, theca.ErrRollback) {
		t.Fatalf("control: a bound old copy: %v %q", r.e, r.out)
	}

	// The attack: the copy from BEFORE the counter existed.
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(nil, "info", path, "--counter", "tpm", "--password-file", pw)
	if !errors.Is(r.e, theca.ErrCounterRequired) {
		t.Fatalf("a pre-counter copy opened under --counter tpm (exit %v), the TPM counter (value %d) was never consulted", r.e, f.ctr.v)
	}
	for _, want := range []string{"no rollback counter", "--counter tpm", "older copy"} {
		if !strings.Contains(r.e.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, r.e)
		}
	}
}
