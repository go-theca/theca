package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
)

// cliKey is a security key for the command's tests: discoverable credentials
// answering HMAC-SHA-256(CredRandom, salt). It asks for its PIN through the
// function it was opened with, as a key without a fingerprint does.
type cliKey struct {
	creds   [][]byte
	pin     func() (string, error)
	pins    []string
	closed  int
	failErr error
}

func (k *cliKey) out(cr []byte, salts [][32]byte) [][]byte {
	res := make([][]byte, len(salts))
	for i, s := range salts {
		h := hmac.New(sha256.New, cr)
		h.Write(s[:])
		res[i] = h.Sum(nil)
	}
	return res
}

func (k *cliKey) askPIN() error {
	p, err := k.pin()
	k.pins = append(k.pins, p)
	return err
}

func (k *cliKey) Enroll(_ context.Context, salts [][32]byte) ([][]byte, error) {
	if k.failErr != nil {
		return nil, k.failErr
	}
	if err := k.askPIN(); err != nil {
		return nil, err
	}
	cr := []byte(strings.Repeat("c", 31) + string(rune('0'+len(k.creds))))
	k.creds = append(k.creds, cr)
	return k.out(cr, salts), nil
}

func (k *cliKey) Derive(_ context.Context, salts [][32]byte) ([][][]byte, error) {
	if err := k.askPIN(); err != nil {
		return nil, err
	}
	if len(k.creds) == 0 {
		return nil, theca.ErrNoCredential
	}
	var res [][][]byte
	for _, cr := range k.creds {
		res = append(res, k.out(cr, salts))
	}
	return res, nil
}

func (k *cliKey) Close() error { k.closed++; return nil }

// TestTheRealOpenerIsReached: the default opener goes to the fido2 package.
// With no key attached it fails; with one attached and no PIN function it
// is refused as unusable before any touch is asked. Either way, no gesture.
func TestTheRealOpenerIsReached(t *testing.T) {
	if dev, err := openFIDO(context.Background(), nil); err == nil {
		dev.Close()
		t.Fatal("a key with no way to ask for its PIN was accepted")
	}
}

// withKey makes openFIDO hand out k (or fail with err).
func withKey(t *testing.T, k *cliKey, err error) {
	t.Helper()
	saved := openFIDO
	t.Cleanup(func() { openFIDO = saved })
	openFIDO = func(_ context.Context, pin func() (string, error)) (fidoDevice, error) {
		if err != nil {
			return nil, err
		}
		k.pin = pin
		return k, nil
	}
}

func TestEnrollKeyThenUnlockWithIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	pw := secretFile(t, dir, "pw", "correct horse", 0o600)
	r := run(nil, "create", path, "--size", "64K", "--policy", "2of3", "--password-file", pw)
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	rc := secretFile(t, dir, "rc", strings.TrimSpace(r.out), 0o600)
	pinFile := secretFile(t, dir, "pin", "123456\n", 0o600)
	k := &cliKey{}
	withKey(t, k, nil)

	r = run(nil, "enroll-key", path, "--password-file", pw, "--recovery-file", rc, "--pin-file", pinFile)
	if r.e != nil || !strings.Contains(r.out, "paired with 2 factor(s)") || !strings.Contains(r.err, "Touch the security key twice") {
		t.Fatalf("enroll-key: %v %q %q", r.e, r.out, r.err)
	}
	if k.closed != 1 || len(k.pins) != 1 || k.pins[0] != "123456" {
		t.Fatalf("closed %d, PINs %q (the PIN file's newline must be stripped)", k.closed, k.pins)
	}
	// 2-of-3: the password alone does not open it; with the key it does.
	if r := run(nil, "info", path, "--password-file", pw); !errors.Is(r.e, theca.ErrNoMatch) {
		t.Fatalf("password alone: %v", r.e)
	}
	r = run(nil, "info", path, "--password-file", pw, "--fido2", "--pin-file", pinFile)
	if r.e != nil || !strings.Contains(r.err, "Touch the security key when it blinks") {
		t.Fatalf("password + key: %v %q", r.e, r.err)
	}
	if r := run(nil, "info", path, "--recovery-file", rc, "--fido2", "--pin-file", pinFile); r.e != nil {
		t.Fatalf("recovery + key: %v", r.e)
	}
	if k.closed != 3 {
		t.Fatalf("the key was not released after each unlock: %d", k.closed)
	}
	// The PIN from the terminal when no PIN file is given.
	terminal(t, "123456")
	if r := run(nil, "info", path, "--password-file", pw, "--fido2"); r.e != nil {
		t.Fatalf("terminal PIN: %v", r.e)
	}
}

func TestEnrollKeyRefusals(t *testing.T) {
	dir, path, pw, _ := newContainer(t)
	missing := filepath.Join(dir, "missing")
	pinFile := secretFile(t, dir, "pin", "1", 0o600)
	boom := errors.New("no key attached")

	withKey(t, nil, boom)
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pinFile); !errors.Is(r.e, boom) {
		t.Fatalf("no key: %v", r.e)
	}
	if r := run(nil, "info", path, "--password-file", pw, "--fido2"); !errors.Is(r.e, boom) {
		t.Fatalf("unlock without a key: %v", r.e)
	}
	k := &cliKey{failErr: errors.New("touch timed out")}
	withKey(t, k, nil)
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", pinFile); r.e == nil || k.closed != 1 {
		t.Fatalf("a failed enrolment: %v, key closed %d times", r.e, k.closed)
	}
	k.failErr = nil
	for name, args := range map[string][]string{
		"missing container": {"enroll-key", missing, "--password-file", pw},
		"wrong password":    {"enroll-key", path, "--password-file", secretFile(t, dir, "bad", "nope", 0o600)},
		"missing PW file":   {"enroll-key", path, "--password-file", missing},
		"bad recovery code": {"enroll-key", path, "--recovery-file", secretFile(t, dir, "rcbad", "not a code", 0o600)},
		"bad hint":          {"enroll-key", path, "--password-file", pw, "--hint", "9"},
		"no arg":            {"enroll-key"},
	} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A PIN that cannot be read is the key's failure, surfaced.
	if r := run(nil, "enroll-key", path, "--password-file", pw, "--pin-file", missing); r.e == nil {
		t.Fatal("unreadable PIN file accepted")
	}
	// An empty file is not a container: its salt cannot be read.
	empty := secretFile(t, dir, "empty", "", 0o600)
	if r := run(nil, "enroll-key", empty, "--password-file", pw); r.e == nil {
		t.Fatal("empty container accepted")
	}
}
