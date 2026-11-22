package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

type stored struct {
	ref    string
	secret string
	o      secretsource.StoreOptions
	raw    []byte // the slice itself, to see whether the command wiped it
}

// vault replaces the secret manager's write side; failFor makes the store of
// one reference fail.
func vault(t *testing.T, failFor ...string) *[]stored {
	t.Helper()
	var calls []stored
	oldS, oldG := storeSecret, generateSecret
	t.Cleanup(func() { storeSecret, generateSecret = oldS, oldG })
	storeSecret = func(_ context.Context, ref string, secret []byte, o secretsource.StoreOptions) error {
		for _, f := range failFor {
			if f == ref {
				return errors.New("manager locked")
			}
		}
		calls = append(calls, stored{ref, string(secret), o, secret})
		return nil
	}
	return &calls
}

func TestCreateStoresGeneratedPasswordAndRecoveryCode(t *testing.T) {
	calls := vault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	terminal(t) // any prompt is a failure
	r := run(nil, "create", path, "--size", "64K", "--password-to", "keychain:theca/vault", "--generate", "20", "--recovery-to", "keychain:theca/vault-rc")
	if r.e != nil {
		t.Fatal(r.e, r.err)
	}
	if len(*calls) != 2 || (*calls)[0].ref != "keychain:theca/vault" || len((*calls)[0].secret) != 20 || (*calls)[1].ref != "keychain:theca/vault-rc" {
		t.Fatalf("%+v", *calls)
	}
	pw, rc := (*calls)[0].secret, (*calls)[1].secret
	// The recovery code was bytes all along, and create wiped them (#74).
	if raw := (*calls)[1].raw; len(raw) != len(rc) || !bytes.Equal(raw, make([]byte, len(rc))) {
		t.Errorf("the recovery code buffer was not wiped: %q", raw)
	}
	if r.out != "" || strings.Contains(r.err, pw) || strings.Contains(r.err, rc) {
		t.Errorf("nothing secret is printed: out=%q err=%q", r.out, r.err)
	}
	if !strings.Contains(r.err, "Password stored in keychain:theca/vault") || !strings.Contains(r.err, "Recovery code stored in") {
		t.Errorf("%q", r.err)
	}
	// What was stored opens the container.
	if x := run(nil, "info", path, "--password-file", secretFile(t, dir, "pw", pw, 0o600)); x.e != nil {
		t.Errorf("password: %v", x.e)
	}
	if x := run(nil, "info", path, "--recovery-file", secretFile(t, dir, "rc", rc, 0o600)); x.e != nil {
		t.Errorf("recovery code: %v", x.e)
	}
}

func TestCreateStoresTypedPassword(t *testing.T) {
	calls := vault(t)
	dir := t.TempDir()
	terminal(t, "typed pw", "typed pw")
	r := run(nil, "create", filepath.Join(dir, "c"), "--size", "64K", "--password-to", "secretservice:theca/v", "--replace")
	if r.e != nil || len(*calls) != 1 || (*calls)[0].secret != "typed pw" || !(*calls)[0].o.Replace {
		t.Fatalf("%v %+v", r.e, *calls)
	}
	if !strings.Contains(r.out, "-") { // the recovery code is still printed
		t.Errorf("out %q", r.out)
	}
}

// A failed store of the password must leave no container behind.
func TestCreateStoreFailureLeavesNothing(t *testing.T) {
	vault(t, "keychain:theca/vault")
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	r := run(nil, "create", path, "--size", "64K", "--password-to", "keychain:theca/vault", "--generate", "16")
	if r.e == nil || !strings.Contains(r.e.Error(), "no container was created") || !strings.Contains(r.e.Error(), "manager locked") {
		t.Fatalf("%v", r.e)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a container was left behind: %v", err)
	}
}

// A failed store of the recovery code prints it after all.
func TestCreateRecoveryStoreFailurePrintsTheCode(t *testing.T) {
	calls := vault(t, "keychain:theca/rc")
	dir := t.TempDir()
	path := filepath.Join(dir, "c")
	r := run(nil, "create", path, "--size", "64K", "--password-to", "keychain:theca/vault", "--generate", "16", "--recovery-to", "keychain:theca/rc")
	if r.e == nil || !strings.Contains(r.e.Error(), "manager locked") {
		t.Fatalf("must fail so the person sees it: %v", r.e)
	}
	code := strings.TrimSpace(r.out)
	if code == "" || !strings.Contains(r.err, "only copy") {
		t.Fatalf("out %q err %q", r.out, r.err)
	}
	// The code printed opens the container, and so does the stored password.
	if x := run(nil, "info", path, "--recovery-file", secretFile(t, dir, "rc", code, 0o600)); x.e != nil {
		t.Errorf("printed code: %v", x.e)
	}
	if x := run(nil, "info", path, "--password-file", secretFile(t, dir, "pw", (*calls)[0].secret, 0o600)); x.e != nil {
		t.Errorf("stored password: %v", x.e)
	}
}

// Creating fails after the password was stored: say where it stays.
func TestCreateFailureAfterStoreSaysSo(t *testing.T) {
	vault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "exists")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(nil, "create", path, "--size", "64K", "--password-to", "keychain:theca/vault", "--generate", "16")
	if r.e == nil || !strings.Contains(r.e.Error(), "stays stored in keychain:theca/vault") {
		t.Fatalf("%v", r.e)
	}
	// And a counter that cannot be made.
	r = run(nil, "create", filepath.Join(dir, "c2"), "--size", "64K", "--password-to", "keychain:theca/vault", "--generate", "16", "--counter", "tpm", "--tpm-device", "/nonexistent/tpm")
	if r.e == nil || !strings.Contains(r.e.Error(), "stays stored") {
		t.Errorf("counter failure: %v", r.e)
	}
	if _, err := os.Stat(filepath.Join(dir, "c2")); !os.IsNotExist(err) {
		t.Errorf("container left behind: %v", err)
	}
}

func TestCreateToFlagRefusals(t *testing.T) {
	vault(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "x", 0o600)
	for name, args := range map[string][]string{
		"generate without a destination": {"--generate", "16"},
		"password-to and a file":         {"--password-to", "keychain:a/b", "--password-file", pw},
		"password-to and a manager":      {"--password-to", "keychain:a/b", "--password-from", "keychain:c/d"},
		"generate and a file":            {"--generate", "16", "--password-file", pw},
		"generate and a manager":         {"--generate", "16", "--password-from", "keychain:c/d"},
	} {
		r := run(nil, append([]string{"create", filepath.Join(dir, "c"), "--size", "64K"}, args...)...)
		if r.e == nil {
			t.Errorf("%s accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "c")); !os.IsNotExist(err) {
			t.Errorf("%s: a container was created", name)
		}
	}
	// A generator that fails stops before anything is stored or created.
	generateSecret = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
	if r := run(nil, "create", filepath.Join(dir, "c"), "--size", "64K", "--password-to", "keychain:a/b", "--generate", "16"); r.e == nil || !strings.Contains(r.e.Error(), "no entropy") {
		t.Errorf("%v", r.e)
	}
}
