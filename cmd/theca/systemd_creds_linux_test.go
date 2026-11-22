//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// credsDir stands for the directory a service manager points
// $CREDENTIALS_DIRECTORY at: one file per credential, mode 0600, no trailing
// newline (a credential is exact bytes; theca takes the password as given).
func credsDir(t *testing.T, creds map[string]string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // systemd's own is 0700; secretsource refuses a looser one
		t.Fatal(err)
	}
	for name, v := range creds {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
}

// TestSystemdCredsEveryFromFlag drives the real secretsource (no stub) with
// systemd-creds: references through every -from flag that takes a secret.
func TestSystemdCredsEveryFromFlag(t *testing.T) {
	terminal(t) // any prompt is a failure
	credsDir(t, map[string]string{"theca": "correct horse"})
	path := filepath.Join(t.TempDir(), "c")
	r := run(nil, "create", path, "--size", "64K", "--password-from", "systemd-creds:theca")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	code := strings.ToLower(strings.TrimSpace(r.out))
	for _, cmd := range []string{"info", "verify"} {
		if r := run(nil, cmd, path, "--password-from", "systemd-creds:theca"); r.e != nil {
			t.Errorf("%s: %v %s", cmd, r.e, r.err)
		}
	}
	if r := run([]byte("hello"), "import", path, "--password-from", "systemd-creds:theca"); r.e != nil {
		t.Errorf("import: %v %s", r.e, r.err)
	}
	// --recovery-from reads the recovery code the same way.
	credsDir(t, map[string]string{"theca-recovery": code})
	if r := run(nil, "info", path, "--recovery-from", "systemd-creds:theca-recovery"); r.e != nil {
		t.Errorf("recovery-from: %v %s", r.e, r.err)
	}
	// A wrong password is refused, not skipped.
	credsDir(t, map[string]string{"theca": "wrong"})
	if r := run(nil, "info", path, "--password-from", "systemd-creds:theca"); r.e == nil {
		t.Error("a wrong credential opened the container")
	}
	// An absent credential is an error naming the reference.
	credsDir(t, map[string]string{})
	t.Setenv("PATH", t.TempDir()) // no systemd-creds to fall back on
	if r := run(nil, "info", path, "--password-from", "systemd-creds:theca"); r.e == nil {
		t.Error("an absent credential opened the container")
	}
}
