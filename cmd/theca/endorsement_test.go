package main

import (
	"bytes"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-tpm2/devtpm"
	"github.com/go-tpm2/tpm2"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/tpmcounter"
)

// The secret-manager flags of the counter reach the TPM; the counter's
// authValue is derived from the container unless the user gives one; a file:
// reference is refused for the new flags.
func TestTPMManagerFlagsAndDerivedAuth(t *testing.T) {
	f := installFakeTPM(t)
	manager(t, map[string]string{
		"keychain:t/ek": "ek-pw", "keychain:t/owner": "owner-pw", "keychain:t/ix": "ix-pw",
	})
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	ek := []string{"--tpm-endorsement-auth-from", "keychain:t/ek"}

	// Create, no counter-auth flag: derived.
	r := run(nil, append([]string{"create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm",
		"--tpm-owner-auth-from", "keychain:t/owner"}, ek...)...)
	if r.e != nil || !strings.Contains(r.err, "derived from the container's master key") {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	c := f.created[0]
	if string(c.EndorsementAuth) != "ek-pw" || string(c.OwnerAuth) != "owner-pw" || len(c.Auth) != 32 {
		t.Fatalf("created with %+v", c)
	}
	// A mount: nothing but the endorsement password is given, the counter's
	// authValue is the one derived at create.
	r = run(nil, append([]string{"info", path, "--password-file", pw, "--counter", "tpm"}, ek...)...)
	if r.e != nil || !strings.Contains(r.out, "counter authValue: derived") {
		t.Fatalf("info: %v %q", r.e, r.out)
	}
	o := f.opened[len(f.opened)-1]
	if string(o.EndorsementAuth) != "ek-pw" || !bytes.Equal(o.Auth, c.Auth) || len(o.OwnerAuth) != 0 {
		t.Fatalf("opened with %+v, created with %+v", o, c)
	}

	// A counter authValue the user gives is used as it is, and the header says so.
	p2 := filepath.Join(dir, "d.theca")
	r = run(nil, "create", p2, "--size", "1M", "--password-file", pw, "--counter", "tpm", "--tpm-auth-from", "keychain:t/ix")
	if r.e != nil || !strings.Contains(r.err, "counter authValue: given with") || string(f.created[len(f.created)-1].Auth) != "ix-pw" {
		t.Fatalf("explicit: %v %q", r.e, r.err)
	}
	// A mount of it with no flag finds an EMPTY authValue (the old behaviour).
	if r = run(nil, "info", p2, "--password-file", pw, "--counter", "tpm"); r.e != nil || len(f.opened[len(f.opened)-1].Auth) != 0 {
		t.Fatalf("explicit, no flag: %v", r.e)
	}
	// Migration: rebind with no authValue flag derives one, the next mount needs none.
	r = run(nil, "counter", "rebind", p2, "--password-file", pw, "--counter", "tpm")
	if r.e != nil || !strings.Contains(r.err, "derived from the container's master key") || len(f.created[len(f.created)-1].Auth) != 32 {
		t.Fatalf("migrate: %v %q", r.e, r.err)
	}
	if r = run(nil, "info", p2, "--password-file", pw, "--counter", "tpm"); r.e != nil || !strings.Contains(r.out, "counter authValue: derived") {
		t.Fatalf("after migration: %v %q", r.e, r.out)
	}
	// Rebind with the endorsement and owner passwords, explicit authValue kept.
	n := len(f.created)
	r = run(nil, append([]string{"counter", "rebind", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-from", "keychain:t/ix",
		"--tpm-owner-auth-from", "keychain:t/owner"}, ek...)...)
	if r.e != nil || len(f.created) != n+1 || string(f.created[n].Auth) != "ix-pw" || string(f.created[n].EndorsementAuth) != "ek-pw" {
		t.Fatalf("rebind: %v %+v", r.e, f.created[n:])
	}

	// A file: reference is refused for each new flag, a bad one is named, and
	// the deprecated file flags exclude their -from twin.
	for _, flag := range []string{"--tpm-endorsement-auth-from", "--tpm-owner-auth-from"} {
		r = run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm", flag, "file:"+pw)
		if r.e == nil || !strings.Contains(r.e.Error(), "a file: reference is refused") || !strings.Contains(r.e.Error(), flag[2:]) {
			t.Errorf("%s file:: %v", flag, r.e)
		}
		r = run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm", flag, "nonsense")
		if r.e == nil || !strings.Contains(r.e.Error(), flag[2:]) {
			t.Errorf("%s bad reference: %v", flag, r.e)
		}
		r = run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm", flag, "keychain:t/missing")
		if r.e == nil {
			t.Errorf("%s: a missing entry was accepted", flag)
		}
	}
	if r = run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm",
		"--tpm-auth-from", "keychain:t/missing"); r.e == nil || !strings.Contains(r.e.Error(), "no such entry") {
		t.Errorf("--tpm-auth-from: a missing entry: %v", r.e)
	}
	// A mount does not read the owner password: a missing counter authValue is
	// the only thing it can fail on, and it must.
	if r = run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-from", "keychain:t/missing"); r.e == nil || !strings.Contains(r.e.Error(), "no such entry") {
		t.Errorf("mount with a missing --tpm-auth-from: %v", r.e)
	}
	for _, pair := range [][2]string{{"--tpm-auth-file", "--tpm-auth-from"}, {"--tpm-owner-auth-file", "--tpm-owner-auth-from"}} {
		r = run(nil, "create", filepath.Join(dir, "e.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm", pair[0], pw, pair[1], "keychain:t/ix")
		if r.e == nil || !strings.Contains(r.e.Error(), "none of the others can be") {
			t.Errorf("%v: %v", pair, r.e)
		}
	}
	// A refusal made nothing.
	if _, err := tpmcounter.Open(tpmcounter.Options{Device: filepath.Join(dir, "none"), Handle: 1}); err == nil {
		t.Fatal("control: the real constructor reached a device")
	}
}

// With a counter authValue given, the counter is made first; a failure to make
// it or to make the container leaves nothing behind.
func TestExplicitAuthCreateFailures(t *testing.T) {
	f := installFakeTPM(t)
	manager(t, map[string]string{"keychain:t/ix": "ix-pw"})
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	args := []string{"create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm", "--tpm-auth-from", "keychain:t/ix"}
	f.createErr = tpmcounter.ErrUnsupported
	if r := run(nil, args...); !errors.Is(r.e, tpmcounter.ErrUnsupported) {
		t.Fatalf("no TPM: %v", r.e)
	}
	f.createErr = nil
	f.failIncAt1 = true
	if r := run(nil, args...); r.e == nil || !f.ctr.destroyed {
		t.Fatalf("failed create: %v", r.e)
	}
	// The derived path undoes its counter too, and a counter never made needs no undo.
	f.ctr = nil
	derived := append([]string{}, args[:len(args)-2]...)
	if r := run(nil, derived...); r.e == nil || !f.ctr.destroyed {
		t.Fatalf("failed create, derived: %v", r.e)
	}
	f.createErr = tpmcounter.ErrUnsupported
	if r := run(nil, derived...); !errors.Is(r.e, tpmcounter.ErrUnsupported) {
		t.Fatalf("derived, no TPM: %v", r.e)
	}
}

// The TPM refusing the endorsement password names the flag, at mount, create and
// rebind.
func TestEndorsementAuthRefusalNamesTheFlag(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	if r := run(nil, "create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm"); r.e != nil {
		t.Fatal(r.e)
	}
	refusal := errors.Join(tpmcounter.ErrIdentity, tpmcounter.ErrEndorsementAuth)
	want := []string{"--tpm-endorsement-auth-from", "dictionary-attack lockout", "19.8.1"}
	check := func(what string, r result) {
		t.Helper()
		if !errors.Is(r.e, tpmcounter.ErrEndorsementAuth) {
			t.Fatalf("%s: %v", what, r.e)
		}
		for _, w := range want {
			if !strings.Contains(r.e.Error(), w) {
				t.Errorf("%s: the message does not say %q: %v", what, w, r.e)
			}
		}
		if strings.Contains(r.e.Error(), "do NOT rebind") {
			t.Errorf("%s: an endorsement password refusal advised a rebind: %v", what, r.e)
		}
	}
	f.openErr = refusal
	check("mount", run(nil, "info", path, "--password-file", pw, "--counter", "tpm"))
	f.openErr = nil
	f.createErr = refusal
	check("create", run(nil, "create", filepath.Join(dir, "d.theca"), "--size", "1M", "--password-file", pw, "--counter", "tpm"))
	check("rebind", run(nil, "counter", "rebind", path, "--password-file", pw, "--counter", "tpm"))
}

// rawTPM is a direct connection to a software TPM, for what the CLI cannot do:
// set a hierarchy password, read the lockout counter. Close it before the CLI
// runs: swtpm serves one connection at a time.
func rawTPM(t *testing.T, dev string) (*tpm2.TPM, func()) {
	t.Helper()
	conn, err := net.Dial("unix", strings.TrimPrefix(dev, "unix:"))
	if err != nil {
		t.Fatal(err)
	}
	tr := devtpm.New(conn)
	return tpm2.New(tr), func() { tr.Close() }
}

// The real thing, on swtpm with an endorsement password set (TPM2_HierarchyChangeAuth):
// a pinned container opens with the right password, is refused with a message that
// names the flag without it or with a wrong one, and none of those refusals counts
// toward the dictionary-attack lockout.
func TestEndorsementAuthSwtpm(t *testing.T) {
	dev := startSwtpmDevice(t)
	manager(t, map[string]string{"keychain:t/ek": "ek-secret", "keychain:t/wrong": "not it"})
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	base := []string{"--password-file", pw, "--counter", "tpm", "--tpm-device", dev}
	withEK := func(ref string) []string {
		return append(append([]string{}, base...), "--tpm-endorsement-auth-from", ref)
	}
	// A container pinned to this TPM while its endorsement password is empty.
	if r := run(nil, append([]string{"create", path, "--size", "1M"}, base...)...); r.e != nil {
		t.Fatal(r.e)
	}
	tp, closeTPM := rawTPM(t, dev)
	if err := tp.HierarchyChangeAuth(tpm2.RHEndorsement, nil, []byte("ek-secret")); err != nil {
		t.Fatal(err)
	}
	lockout := func() uint32 {
		p, err := tp.GetTPMProperties(tpm2.PTLockoutCounter, 1)
		if err != nil || len(p) != 1 {
			t.Fatalf("lockout counter: %v %v", p, err)
		}
		return p[0].Value
	}
	before := lockout()
	closeTPM()

	// The password was set after the container was made: without it, or with a
	// wrong one, the mount is refused and says why.
	for name, args := range map[string][]string{"none": base, "wrong": withEK("keychain:t/wrong")} {
		r := run(nil, append([]string{"info", path}, args...)...)
		if !errors.Is(r.e, tpmcounter.ErrEndorsementAuth) || !errors.Is(r.e, theca.ErrCounterIdentity) ||
			!strings.Contains(r.e.Error(), "--tpm-endorsement-auth-from") {
			t.Fatalf("%s: %v", name, r.e)
		}
	}
	// The right one opens it, and several mounts in a row stay possible.
	for i := 0; i < 3; i++ {
		r := run(nil, append([]string{"info", path}, withEK("keychain:t/ek")...)...)
		if r.e != nil || !strings.Contains(r.out, "rollback protected: true") || !strings.Contains(r.out, "counter authValue: derived") {
			t.Fatalf("right password, mount %d: %v %q", i, r.e, r.out)
		}
	}
	// Rebind needs it too, and pins the same TPM again.
	if r := run(nil, append([]string{"counter", "rebind", path}, base...)...); !errors.Is(r.e, tpmcounter.ErrEndorsementAuth) {
		t.Fatalf("rebind without it: %v", r.e)
	}
	r := run(nil, append([]string{"counter", "rebind", path}, withEK("keychain:t/ek")...)...)
	if r.e != nil || !strings.Contains(r.err, "counter TPM identity") {
		t.Fatalf("rebind with it: %v %q", r.e, r.err)
	}
	if r := run(nil, append([]string{"info", path}, withEK("keychain:t/ek")...)...); r.e != nil {
		t.Fatalf("mount after the rebind: %v", r.e)
	}
	// A container CREATED under the password pins the same identity.
	p2 := filepath.Join(dir, "d.theca")
	if r := run(nil, append([]string{"create", p2, "--size", "1M"}, withEK("keychain:t/ek")...)...); r.e != nil {
		t.Fatalf("create under the password: %v %q", r.e, r.err)
	}
	if r := run(nil, append([]string{"create", filepath.Join(dir, "e.theca"), "--size", "1M"}, base...)...); !errors.Is(r.e, tpmcounter.ErrEndorsementAuth) {
		t.Fatalf("create without it: %v", r.e)
	}
	// None of the refusals was an authorization failure that counts (TCG Part 1
	// rev 1.59, 19.8.1: a hierarchy authValue is not DA protected).
	tp, closeTPM = rawTPM(t, dev)
	defer closeTPM()
	if after := lockout(); after != before {
		t.Fatalf("failedTries %d -> %d: a refused endorsement password counted toward the lockout", before, after)
	}
}
