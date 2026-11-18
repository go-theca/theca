package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// manager replaces the secret manager: reference -> secret.
func manager(t *testing.T, refs map[string]string) *[]string {
	t.Helper()
	var asked []string
	saved := readRef
	t.Cleanup(func() { readRef = saved })
	readRef = func(_ context.Context, ref string) ([]byte, error) {
		asked = append(asked, ref)
		if v, ok := refs[ref]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("secretsource: no such entry: " + ref)
	}
	return &asked
}

func TestPasswordFromCreateAndOpen(t *testing.T) {
	asked := manager(t, map[string]string{"keychain:theca/pw": "correct horse"})
	terminal(t) // any prompt is a failure: the terminal has no answers
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	// create does not ask twice: a manager's secret is not typed.
	r := run(nil, "create", path, "--size", "64K", "--password-from", "keychain:theca/pw")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	code := strings.TrimSpace(r.out)
	for _, cmd := range []string{"info", "verify"} {
		if r := run(nil, cmd, path, "--password-from", "keychain:theca/pw"); r.e != nil {
			t.Errorf("%s: %v %s", cmd, r.e, r.err)
		}
	}
	// import needs a non-terminal secret: --password-from counts.
	if r := run([]byte("hello"), "import", path, "--password-from", "keychain:theca/pw"); r.e != nil {
		t.Errorf("import: %v %s", r.e, r.err)
	}
	// The same password from a file opens it too.
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	if r := run(nil, "info", path, "--password-file", pw); r.e != nil {
		t.Errorf("file: %v", r.e)
	}
	// The recovery code from a manager.
	asked2 := manager(t, map[string]string{"secretservice:theca/rc": strings.ToLower(code)})
	if r := run(nil, "info", path, "--recovery-from", "secretservice:theca/rc"); r.e != nil {
		t.Errorf("recovery-from: %v %s", r.e, r.err)
	}
	if len(*asked) == 0 || len(*asked2) == 0 {
		t.Error("the manager was never asked")
	}
}

func TestFromRefusals(t *testing.T) {
	manager(t, map[string]string{"keychain:theca/pw": "x"})
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	pw := secretFile(t, dir, "pw", "x", 0o600)
	for _, args := range [][]string{
		{"info", path, "--password-file", pw, "--password-from", "keychain:a/b"},
		{"info", path, "--recovery-file", pw, "--recovery-from", "keychain:a/b"},
		{"info", path, "--fido2", "--pin-file", pw, "--pin-from", "keychain:a/b"},
		{"slots", "list", path, "--password-file", pw, "--password-from", "keychain:a/b"},
	} {
		if r := run(nil, args...); r.e == nil || !strings.Contains(r.e.Error(), "none of the others can be") {
			t.Errorf("%v: both flags must be refused: %v", args, r.e)
		}
	}
	// A missing entry is the error, not a prompt.
	terminal(t)
	if r := run(nil, "create", path, "--size", "64K", "--password-from", "keychain:missing/x"); r.e == nil || !strings.Contains(r.e.Error(), "no such entry") {
		t.Errorf("missing: %v", r.e)
	}
}

func TestPinFromReachesTheKey(t *testing.T) {
	manager(t, map[string]string{"secretservice:fido/key": "246810", "keychain:theca/pw": "correct horse"})
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	if r := run(nil, "create", path, "--size", "64K", "--password-from", "keychain:theca/pw"); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	k := &cliKey{}
	withKey(t, k, nil)
	if r := run(nil, "enroll-key", path, "--password-from", "keychain:theca/pw", "--pin-from", "secretservice:fido/key"); r.e != nil {
		t.Fatal(r.e, r.err)
	}
	if len(k.pins) == 0 || k.pins[0] != "246810" {
		t.Errorf("the key was asked with %q", k.pins)
	}
}

func TestOpenRefDefault(t *testing.T) {
	if _, err := openRef(context.Background(), "no-scheme"); err == nil {
		t.Error("a scheme-less reference must be refused")
	}
	dir := t.TempDir()
	if b, err := openRef(context.Background(), "file:"+secretFile(t, dir, "s", "abc\n", 0o600)); err != nil || string(b) != "abc" {
		t.Errorf("%q %v", b, err)
	}
}
