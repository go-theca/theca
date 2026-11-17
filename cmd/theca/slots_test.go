package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-theca/theca"
)

func TestSlotsListAndRemove(t *testing.T) {
	dir, path, pw, code := newContainer(t)
	rc := secretFile(t, dir, "rc", code, 0o600)

	r := run(nil, "slots", "list", path, "--password-file", pw, "--recovery-file", rc)
	if r.e != nil || !strings.Contains(r.out, "recorded slots: ") || !strings.Contains(r.out, "(2 of 16)") ||
		!strings.Contains(r.out, "opened by the password: ") || !strings.Contains(r.out, "opened by the recovery: ") ||
		!strings.Contains(r.out, "opened by the password+recovery: none") {
		t.Fatalf("list: %v %q", r.e, r.out)
	}
	// Only the password presented: only it is listed.
	r = run(nil, "slots", "list", path, "--password-file", pw)
	if r.e != nil || strings.Contains(r.out, "recovery") {
		t.Fatalf("list, password only: %v %q", r.e, r.out)
	}

	// Refusals write nothing.
	for name, args := range map[string][]string{
		"no flags":            {"slots", "remove", path, "--password-file", pw, "--recovery-file", rc},
		"same set":            {"slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "password", "--keep", "password"},
		"keep opens nothing":  {"slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "recovery", "--keep", "password+recovery"},
		"unknown set":         {"slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "key", "--keep", "password"},
		"unknown keep":        {"slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "recovery", "--keep", "key"},
		"recovery not given":  {"slots", "remove", path, "--password-file", pw, "--remove", "recovery", "--keep", "password"},
		"password not given":  {"slots", "remove", path, "--recovery-file", rc, "--remove", "recovery", "--keep", "password"},
		"wrong password":      {"slots", "remove", path, "--password-file", secretFile(t, dir, "bad", "nope", 0o600), "--remove", "recovery", "--keep", "password"},
		"no such file":        {"slots", "remove", dir + "/missing", "--password-file", pw, "--remove", "recovery", "--keep", "password"},
		"unreadable recovery": {"slots", "remove", path, "--password-file", pw, "--recovery-file", dir + "/missing", "--remove", "recovery", "--keep", "password"},
	} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if r := run(nil, "slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "password", "--keep", "password"); r.e == nil || !strings.Contains(r.e.Error(), "last way in") {
		t.Fatalf("same set: %v", r.e)
	}
	// A bad hint, a bad recovery code and a file too short to be a container.
	short := dir + "/short"
	if err := os.WriteFile(short, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := secretFile(t, dir, "junk", "not a recovery code", 0o600)
	for name, args := range map[string][]string{
		"bad hint":          {"slots", "list", path, "--password-file", pw, "--hint", "9"},
		"bad recovery code": {"slots", "list", path, "--password-file", pw, "--recovery-file", junk},
		"short file":        {"slots", "list", short, "--password-file", pw},
	} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A failure while trial-opening the slots is reported.
	saved := slotsOf
	t.Cleanup(func() { slotsOf = saved })
	slotsOf = func(*theca.Container, ...theca.Factor) ([]int, error) { return nil, errors.New("boom") }
	if r := run(nil, "slots", "list", path, "--password-file", pw); r.e == nil || !strings.Contains(r.e.Error(), "boom") {
		t.Fatalf("list with a failing SlotsOf: %v", r.e)
	}
	slotsOf = saved
	if r := run(nil, "verify", path, "--recovery-file", rc); r.e != nil {
		t.Fatalf("the recovery code stopped working after refusals: %v", r.e)
	}

	// Remove the recovery code, keeping the password.
	r = run(nil, "slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "recovery", "--keep", "password")
	if r.e != nil || !strings.Contains(r.out, "ok: removed 1 slot(s)") || !strings.Contains(r.err, "older copy") {
		t.Fatalf("remove: %v %q %q", r.e, r.out, r.err)
	}
	if r := run(nil, "verify", path, "--recovery-file", rc); r.e == nil {
		t.Fatal("the removed recovery code still opens the container")
	}
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("the password stopped working: %v", r.e)
	}
	// Removing it again: nothing opens with it (it no longer opens the container).
	if r := run(nil, "slots", "remove", path, "--password-file", pw, "--recovery-file", rc, "--remove", "recovery", "--keep", "password"); r.e == nil {
		t.Fatal("removed twice")
	}
}
