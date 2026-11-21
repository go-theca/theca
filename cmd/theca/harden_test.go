package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/go-theca/theca/internal/memlock"
)

// The in-process daemon tests must not deny a debugger to the test binary, nor
// drop its core limit: they run hardenProcess with the platform call replaced.
func init() { platformHarden = func() error { return nil } }

// The recovery code is carried as bytes and wiped with the password.
func TestUnlockWipesThePasswordAndTheRecoveryCode(t *testing.T) {
	dir, _, _, code := newContainer(t)
	rc := secretFile(t, dir, "rc", code+"\n", 0o600)
	pw := secretFile(t, dir, "pw2", "correct horse\n", 0o600)
	cmd := RootCmd()
	s := &secrets{passwordFile: pw, recoveryFile: rc}
	u, wipe, err := s.unlock(cmd)
	if err != nil || len(u.Recovery) == 0 || len(u.Password) == 0 {
		t.Fatalf("unlock: %v %q %q", err, u.Recovery, u.Password)
	}
	rec, pass := u.Recovery, u.Password
	wipe()
	if !bytes.Equal(rec, make([]byte, len(rec))) || !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatalf("not wiped: %q %q", rec, pass)
	}
}

func TestMlockFlag(t *testing.T) {
	_, path, pw, _ := newContainer(t)
	restore := memlock.SetSyscalls(func(unsafe.Pointer, uintptr) error { return errors.New("cannot allocate memory") },
		func(unsafe.Pointer, uintptr) {})
	defer func() { restore(); memlock.SetMode(memlock.BestEffort); memlock.SetReporter(nil) }()

	if r := run(nil, "info", path, "--mlock", "maybe"); r.e == nil || !strings.Contains(r.e.Error(), `"maybe"`) {
		t.Fatalf("a bad mode: %v", r.e)
	}
	r := run(nil, "export", path, "--password-file", pw, "--length", "16")
	if r.e != nil || strings.Count(r.err, "warning:") != 1 || !strings.Contains(r.err, "cannot allocate memory") {
		t.Fatalf("auto: %v %q", r.e, r.err)
	}
	if r := run(nil, "export", path, "--password-file", pw, "--length", "16", "--mlock", "off"); r.e != nil || strings.Contains(r.err, "warning:") {
		t.Fatalf("off: %v %q", r.e, r.err)
	}
	if r := run(nil, "export", path, "--password-file", pw, "--length", "16", "--mlock", "required"); r.e == nil || !strings.Contains(r.e.Error(), "cannot allocate memory") {
		t.Fatalf("required: %v", r.e)
	}
}

func TestHardenProcessSaysWhichProtectionIsMissing(t *testing.T) {
	var w bytes.Buffer
	hardenProcess(&w)
	if w.Len() != 0 {
		t.Fatalf("a successful hardening printed %q", w.String())
	}
	saved := platformHarden
	defer func() { platformHarden = saved }()
	platformHarden = func() error { return errors.New("operation not permitted") }
	hardenProcess(&w)
	if !strings.Contains(w.String(), "operation not permitted") || !strings.Contains(w.String(), "core file") {
		t.Fatalf("warning: %q", w.String())
	}
}
