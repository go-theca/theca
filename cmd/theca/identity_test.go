package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/tpmcounter"
)

func TestCLITPMIdentity(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	owner := secretFile(t, dir, "owner", "owner secret\n", 0o600)
	flags := []string{"--password-file", pw, "--counter", "tpm", "--tpm-owner-auth-file", owner}

	// A container made now is pinned, and says so at create and at info.
	f.tpmID = bytes.Repeat([]byte{0x11}, 32)
	pinned := filepath.Join(dir, "pinned.theca")
	r := run(nil, append([]string{"create", pinned, "--size", "1M"}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "counter TPM identity: 111111111111") {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	r = run(nil, append([]string{"info", pinned}, flags...)...)
	if r.e != nil || !strings.Contains(r.out, "counter TPM identity: 111111111111") || strings.Contains(r.err, "not pinned") {
		t.Fatalf("info: %v %q %q", r.e, r.out, r.err)
	}

	// Another TPM: refused, naming both, with the recovery, and the warning
	// not to rebind when the TPM was not replaced.
	f.tpmID = bytes.Repeat([]byte{0x22}, 32)
	r = run(nil, append([]string{"info", pinned}, flags...)...)
	if !errors.Is(r.e, theca.ErrCounterIdentity) {
		t.Fatalf("another TPM: %v", r.e)
	}
	for _, want := range []string{"111111111111", "222222222222", "counter rebind", "do NOT rebind"} {
		if !strings.Contains(r.e.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, r.e)
		}
	}
	// The recovery works and pins the new TPM.
	r = run(nil, append([]string{"counter", "rebind", pinned}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "counter TPM identity: 222222222222") {
		t.Fatalf("rebind: %v %q", r.e, r.err)
	}
	if r = run(nil, append([]string{"info", pinned}, flags...)...); r.e != nil || !strings.Contains(r.out, "222222222222") {
		t.Fatalf("after the rebind: %v %q", r.e, r.out)
	}

	// A container made before the pin (a counter that cannot name its TPM)
	// still opens, with a stated warning, until it is rebound.
	f.tpmID = nil
	old := filepath.Join(dir, "old.theca")
	if r = run(nil, append([]string{"create", old, "--size", "1M"}, flags...)...); r.e != nil || !strings.Contains(r.err, "not pinned") {
		t.Fatalf("create without identity: %v %q", r.e, r.err)
	}
	r = run(nil, append([]string{"info", old}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "warning: this container's rollback counter is not pinned to a TPM identity") ||
		!strings.Contains(r.out, "counter TPM identity: not pinned") || !strings.Contains(r.out, "rollback protected: true") {
		t.Fatalf("old container: %v out %q err %q", r.e, r.out, r.err)
	}
	// Rebind with an identified TPM pins it.
	f.tpmID = bytes.Repeat([]byte{0x33}, 32)
	r = run(nil, append([]string{"counter", "rebind", old}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "counter TPM identity: 333333333333") {
		t.Fatalf("rebind of an old container: %v %q", r.e, r.err)
	}
	if r = run(nil, append([]string{"info", old}, flags...)...); r.e != nil || strings.Contains(r.err, "not pinned") {
		t.Fatalf("after pinning: %v %q", r.e, r.err)
	}
}

// The attack of go-theca/theca#39 through the CLI, on two software TPMs: the
// second one has the same index, the same Name and the value of the old copy.
func TestCLISwtpmAnotherTPMIsRefused(t *testing.T) {
	devA, devB := startSwtpmDevice(t), startSwtpmDevice(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	// The counter's authValue is given (not derived), so the test can read it
	// from outside, as the attacker would have to.
	ix := secretFile(t, dir, "ix", "index secret\n", 0o600)
	flags := func(d string) []string {
		return []string{"--password-file", pw, "--counter", "tpm", "--tpm-device", d, "--tpm-auth-file", ix}
	}
	if r := run(nil, append([]string{"create", path, "--size", "1M"}, flags(devA)...)...); r.e != nil || !strings.Contains(r.err, "counter TPM identity: ") {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	a, err := tpmcounter.Open(tpmcounter.Options{Device: devA, Handle: tpmcounter.First, Auth: []byte("index secret")})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := a.Read()
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's TPM: the same handle, raised to the bound.
	b, err := tpmcounter.Create(tpmcounter.Options{Device: devB, Auth: []byte("index secret")})
	if err != nil {
		t.Fatal(err)
	}
	for v := uint64(0); v < bound; {
		if err := b.Increment(); err != nil {
			t.Fatal(err)
		}
		if v, err = b.Read(); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(a.Name(), b.Name()) || b.Handle() != a.Handle() {
		t.Fatalf("the attack needs the same index: %x/%x", a.Name(), b.Name())
	}
	r := run(nil, append([]string{"info", path}, flags(devB)...)...)
	if !errors.Is(r.e, theca.ErrCounterIdentity) || !strings.Contains(r.e.Error(), "counter rebind") {
		t.Fatalf("another TPM: %v", r.e)
	}
	if v, _ := b.Read(); v != bound {
		t.Fatalf("the refused mount moved the counter of the other TPM: %d -> %d", bound, v)
	}
	// Its own TPM opens it.
	if r := run(nil, append([]string{"info", path}, flags(devA)...)...); r.e != nil || !strings.Contains(r.out, "counter TPM identity: ") {
		t.Fatalf("own TPM: %v %q", r.e, r.out)
	}
}
