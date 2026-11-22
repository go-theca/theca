package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
	"github.com/go-tpm2/nvcounter"
)

// fakeCounter is a TPM NV counter in memory. Its Name changes once, at the
// first increment, as a real one does (the WRITTEN attribute is part of it).
type fakeCounter struct {
	h         uint32
	v         uint64
	written   bool
	incErr    error
	destroyed bool
}

func (c *fakeCounter) Handle() uint32 { return c.h }
func (c *fakeCounter) Name() []byte {
	if c.written {
		return []byte{0, 0x0B, 1}
	}
	return []byte{0, 0x0B, 0}
}
func (c *fakeCounter) Read() (uint64, error) { return c.v, nil }
func (c *fakeCounter) Increment() error {
	if c.incErr != nil {
		return c.incErr
	}
	c.v++
	c.written = true
	return nil
}
func (c *fakeCounter) Destroy() error { c.destroyed = true; return nil }

// fakeTPM installs a fake TPM behind the counter flags and records the
// options the CLI passed.
type fakeTPM struct {
	ctr        *fakeCounter
	created    []nvcounter.Options
	opened     []nvcounter.Options
	createErr  error
	openErr    error
	failIncAt1 bool
	failHandle uint32 // createCounter refuses this handle (taken)
	removeErr  error
	removed    []uint32 // handles removeCounter was asked about
	tpmID      []byte   // when set, the counters name their TPM with it
}

// identFake is a counter that names its TPM.
type identFake struct {
	*fakeCounter
	id []byte
}

func (c identFake) Identity() ([]byte, error) { return c.id, nil }

// seen returns f.ctr as the CLI sees it: identified when f.tpmID is set.
func (f *fakeTPM) seen() tpmCounter {
	if f.tpmID != nil {
		return identFake{f.ctr, f.tpmID}
	}
	return f.ctr
}

func installFakeTPM(t *testing.T) *fakeTPM {
	t.Helper()
	f := &fakeTPM{}
	sc, so, sr := createCounter, openCounter, removeCounter
	t.Cleanup(func() { createCounter, openCounter, removeCounter = sc, so, sr })
	removeCounter = func(o nvcounter.Options) (bool, error) {
		f.removed = append(f.removed, o.Handle)
		if f.removeErr != nil {
			return false, f.removeErr
		}
		if f.ctr != nil && f.ctr.h == o.Handle && !f.ctr.destroyed {
			f.ctr.destroyed = true
			return true, nil
		}
		return false, nil
	}
	createCounter = func(o nvcounter.Options) (tpmCounter, error) {
		o.Auth, o.OwnerAuth, o.EndorsementAuth = append([]byte(nil), o.Auth...), append([]byte(nil), o.OwnerAuth...), append([]byte(nil), o.EndorsementAuth...) // the CLI wipes its copies
		f.created = append(f.created, o)
		if f.createErr != nil {
			return nil, f.createErr
		}
		h := o.Handle
		if h != 0 && h == f.failHandle {
			return nil, errors.New("NV index already defined")
		}
		if h == 0 {
			h = 0x01500000
		}
		f.ctr = &fakeCounter{h: h, v: 40}
		if f.failIncAt1 {
			f.ctr.incErr = errors.New("increment refused")
		}
		return f.seen(), nil
	}
	openCounter = func(o nvcounter.Options) (theca.Counter, error) {
		o.Auth, o.OwnerAuth, o.EndorsementAuth = append([]byte(nil), o.Auth...), append([]byte(nil), o.OwnerAuth...), append([]byte(nil), o.EndorsementAuth...)
		f.opened = append(f.opened, o)
		if f.openErr != nil {
			return nil, f.openErr
		}
		return f.seen(), nil
	}
	return f
}

func TestCounterTPMLifecycle(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	auth := secretFile(t, dir, "auth", "index secret\n", 0o600)
	owner := secretFile(t, dir, "owner", "owner secret\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	r := run(nil, "create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm",
		"--tpm-handle", "0x01500042", "--tpm-auth-file", auth, "--tpm-owner-auth-file", owner, "--tpm-device", "unix:/x")
	if r.e != nil || !strings.Contains(r.err, "rollback counter: TPM NV index 0x01500042") || strings.Contains(r.err, "no rollback counter") {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	o := f.created[0]
	if o.Handle != 0x01500042 || string(o.Auth) != "index secret" || string(o.OwnerAuth) != "owner secret" || o.Device != "unix:/x" {
		t.Fatalf("options %+v", o)
	}
	if f.ctr.v != 41 || f.ctr.destroyed {
		t.Fatalf("counter %d destroyed %v", f.ctr.v, f.ctr.destroyed)
	}

	// Without the flag the refusal names it.
	r = run(nil, "info", path, "--password-file", pw)
	if !errors.Is(r.e, theca.ErrCounter) || !strings.Contains(r.e.Error(), "--counter tpm") {
		t.Fatalf("info without the flag: %v", r.e)
	}
	// With it: protected, and one mount moved the counter once.
	r = run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth)
	if r.e != nil || !strings.Contains(r.out, "rollback protected: true (TPM NV counter 0x01500042") || strings.Contains(r.err, "no rollback counter") {
		t.Fatalf("info: %v %q %q", r.e, r.out, r.err)
	}
	if f.ctr.v != 42 || f.opened[0].Handle != 0x01500042 || string(f.opened[0].Auth) != "index secret" {
		t.Fatalf("after a mount: counter %d, opened %+v", f.ctr.v, f.opened)
	}
	if len(f.opened[0].OwnerAuth) != 0 {
		t.Fatal("the owner password was given to an open")
	}
	// Every open command takes it.
	for _, args := range [][]string{{"verify"}, {"export"}, {"slots", "list"}} {
		a := append(append([]string{}, args...), path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth)
		if r := run(nil, a...); r.e != nil {
			t.Fatalf("%v: %v %s", args, r.e, r.err)
		}
	}

	// An older copy is refused, and --accept-rollback is loud.
	older, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := run(nil, "verify", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth); r.e != nil {
		t.Fatal(r.e)
	}
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth)
	if !errors.Is(r.e, theca.ErrRollback) {
		t.Fatalf("rolled-back copy: %v", r.e)
	}
	r = run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", auth, "--accept-rollback")
	if r.e != nil || !strings.Contains(r.err, "warning: --accept-rollback") {
		t.Fatalf("accept-rollback: %v %q", r.e, r.err)
	}
}

func TestCounterTPMErrors(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	create := func(extra ...string) result {
		return run(nil, append([]string{"create", path, "--size", "1M", "--password-file", pw}, extra...)...)
	}
	for _, c := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"unknown counter", []string{"--counter", "sgx"}, "want tpm"},
		{"missing auth file", []string{"--counter", "tpm", "--tpm-auth-file", filepath.Join(dir, "none")}, "no such file"},
		{"missing owner file", []string{"--counter", "tpm", "--tpm-owner-auth-file", filepath.Join(dir, "none")}, "no such file"},
		{"loose auth file", []string{"--counter", "tpm", "--tpm-auth-file", secretFile(t, dir, "loose", "x", 0o644)}, "must not be readable"},
	} {
		if r := create(c.extra...); r.e == nil || !strings.Contains(r.e.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, r.e)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s left a container behind", c.name)
		}
	}
	f.createErr = nvcounter.ErrUnsupported
	if r := create("--counter", "tpm"); !errors.Is(r.e, nvcounter.ErrUnsupported) {
		t.Fatalf("no TPM: %v", r.e)
	}
	f.createErr = nil
	// The container cannot be made: the counter is deleted again.
	f.failIncAt1 = true
	if r := create("--counter", "tpm"); r.e == nil || !f.ctr.destroyed {
		t.Fatalf("failed create: %v destroyed %v", r.e, f.ctr != nil && f.ctr.destroyed)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a failed create left a container behind")
	}
	f.failIncAt1 = false
	if r := create("--counter", "tpm"); r.e != nil {
		t.Fatal(r.e)
	}
	// Opening: the TPM is unreachable, or the credentials are unreadable.
	f.openErr = nvcounter.ErrNotCounter
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "tpm"); !errors.Is(r.e, nvcounter.ErrNotCounter) {
		t.Fatalf("open: %v", r.e)
	}
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", filepath.Join(dir, "none")); r.e == nil {
		t.Fatal("an unreadable authValue file was accepted")
	}
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "sgx"); r.e == nil {
		t.Fatal("an unknown counter was accepted")
	}
}

// The counter is gone: the refusal names the recovery, `counter rebind` does it.
func TestCounterRebind(t *testing.T) {
	f := installFakeTPM(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	owner := secretFile(t, dir, "owner", "owner secret\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	if r := run(nil, "create", path, "--size", "1M", "--password-file", pw, "--counter", "tpm", "--tpm-handle", "0x01500042"); r.e != nil {
		t.Fatal(r.e)
	}
	old := f.ctr
	info := func() result {
		return run(nil, "info", path, "--password-file", pw, "--counter", "tpm")
	}

	// The index is gone (undefined, or the TPM was cleared).
	f.openErr = nvcounter.ErrNoCounter
	if r := info(); !errors.Is(r.e, nvcounter.ErrNoCounter) || !strings.Contains(r.e.Error(), "counter rebind") {
		t.Fatalf("refusal after the counter was deleted: %v", r.e)
	}
	// --accept-rollback is not the way back (it needs a counter to compare).
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--accept-rollback"); !errors.Is(r.e, nvcounter.ErrNoCounter) {
		t.Fatalf("accept-rollback with no counter: %v", r.e)
	}
	// A counter that is there but is not the recorded one: the same sentence.
	f.openErr = nil
	f.ctr = &fakeCounter{h: 0x01500042, v: 9, written: true}
	f.ctr.written = false // its Name differs from the recorded one
	if r := info(); !errors.Is(r.e, theca.ErrCounter) || !strings.Contains(r.e.Error(), "counter rebind") {
		t.Fatalf("another counter at the handle: %v", r.e)
	}
	f.openErr = nvcounter.ErrNotCounter
	if r := info(); !strings.Contains(r.e.Error(), "counter rebind") {
		t.Fatalf("not a counter: %v", r.e)
	}
	f.openErr = nil
	f.ctr = old

	// Rebind: at the recorded handle when it is free.
	f.created = nil
	rb := func(extra ...string) result {
		return run(nil, append([]string{"counter", "rebind", path, "--password-file", pw, "--counter", "tpm", "--tpm-owner-auth-file", owner}, extra...)...)
	}
	f.failHandle = 0
	r := rb()
	if r.e != nil || !strings.Contains(r.err, "NEW TPM counter, NV index 0x01500042") || !strings.Contains(r.err, "restarts from now") {
		t.Fatalf("rebind: %v %q", r.e, r.err)
	}
	if f.created[0].Handle != 0x01500042 || string(f.created[0].OwnerAuth) != "owner secret" || f.ctr == old || f.ctr.v != 41 {
		t.Fatalf("created %+v, counter %+v", f.created, f.ctr)
	}
	// The healthy old counter was deleted first, and the warning says so.
	if !old.destroyed || len(f.removed) != 1 || f.removed[0] != 0x01500042 || !strings.Contains(r.err, "has been DELETED") {
		t.Fatalf("old counter: destroyed %v, asked %x, warning %q", old.destroyed, f.removed, r.err)
	}
	if r := info(); r.e != nil || !strings.Contains(r.out, "rollback protected: true") {
		t.Fatalf("after the rebind: %v %q", r.e, r.out)
	}

	// The old counter cannot be checked or deleted: nothing is made, the rebind stops.
	f.removeErr = errors.New("tpm unreachable")
	n0 := len(f.created)
	if r := rb(); r.e == nil || len(f.created) != n0 {
		t.Fatalf("rebind with an undeletable old counter: %v, created %d more", r.e, len(f.created)-n0)
	}
	f.removeErr = nil
	// The old counter is already absent: said so.
	f.ctr.destroyed = true
	if r := rb(); r.e != nil || !strings.Contains(r.err, "already absent") {
		t.Fatalf("absent old counter: %v %q", r.e, r.err)
	}

	// The recorded handle is taken: the first free one.
	f.failHandle = 0x01500042
	f.created = nil
	r = rb()
	if r.e != nil || len(f.created) != 2 || f.created[1].Handle != 0 || !strings.Contains(r.err, "NV index 0x01500000") {
		t.Fatalf("fallback: %v %q created %+v", r.e, r.err, f.created)
	}
	f.failHandle = 0
	// An explicit handle that is taken is an error, not a fallback.
	f.failHandle = 0x01500099
	f.created = nil
	if r := rb("--tpm-handle", "0x01500099"); r.e == nil || len(f.created) != 1 {
		t.Fatalf("explicit handle: %v, %d attempts", r.e, len(f.created))
	}
	f.failHandle = 0
	// The new counter cannot be made at all.
	f.createErr = nvcounter.ErrUnsupported
	if r := rb(); !errors.Is(r.e, nvcounter.ErrUnsupported) {
		t.Fatalf("no TPM: %v", r.e)
	}
	f.createErr = nil
	// The container cannot be rebound (the new counter cannot increment): the index is deleted again.
	f.failIncAt1 = true
	if r := rb(); r.e == nil || !f.ctr.destroyed {
		t.Fatalf("failed rebind: %v", r.e)
	}
	f.failIncAt1 = false

	// Refusals before anything is made.
	if r := run(nil, "counter", "rebind", path, "--password-file", pw); r.e == nil || !strings.Contains(r.e.Error(), "--counter tpm") {
		t.Fatalf("no --counter: %v", r.e)
	}
	if r := run(nil, "counter", "rebind", path, "--password-file", pw, "--counter", "sgx"); r.e == nil {
		t.Fatal("unknown counter")
	}
	if r := rb("--tpm-owner-auth-file", filepath.Join(dir, "none")); r.e == nil {
		t.Fatal("missing owner file")
	}
	if r := run(nil, "counter", "rebind", filepath.Join(dir, "none.theca"), "--password-file", pw, "--counter", "tpm"); r.e == nil {
		t.Fatal("missing container")
	}
	if r := run(nil, "counter", "rebind", path, "--password-file", filepath.Join(dir, "none"), "--counter", "tpm"); r.e == nil {
		t.Fatal("missing password file")
	}
	n := len(f.created)
	wrong := secretFile(t, dir, "wrong", "not the password\n", 0o600)
	if r := run(nil, "counter", "rebind", path, "--password-file", wrong, "--counter", "tpm"); r.e == nil || len(f.created) != n {
		t.Fatalf("a wrong password made a counter: %v", r.e)
	}
}

// On a software TPM: the counter deleted, then the TPM replaced (what TPM2_Clear
// or a reinstall amounts to: no such index any more). The container is refused
// with the recovery named, `counter rebind` binds it again, and it opens.
func TestCounterTPMSwtpmRecovery(t *testing.T) {
	dev := startSwtpmDevice(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	flags := func(d string) []string { return []string{"--password-file", pw, "--counter", "tpm", "--tpm-device", d} }
	if r := run(nil, append([]string{"create", path, "--size", "1M"}, flags(dev)...)...); r.e != nil {
		t.Fatal(r.e)
	}
	// Delete the index, as the owner can.
	c, err := nvcounter.Open(nvcounter.Options{Device: dev, Handle: 0x01500000})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Destroy(); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, append([]string{"info", path}, flags(dev)...)...); !errors.Is(r.e, nvcounter.ErrNoCounter) || !strings.Contains(r.e.Error(), "counter rebind") {
		t.Fatalf("after the index was deleted: %v", r.e)
	}
	r := run(nil, append([]string{"counter", "rebind", path}, flags(dev)...)...)
	if r.e != nil || !strings.Contains(r.err, "NV index 0x01500000") {
		t.Fatalf("rebind: %v %q", r.e, r.err)
	}
	if r := run(nil, append([]string{"info", path}, flags(dev)...)...); r.e != nil || !strings.Contains(r.out, "rollback protected: true") {
		t.Fatalf("after the rebind: %v %q", r.e, r.out)
	}
	// The protection works again: a copy from before a mount is refused.
	older, _ := os.ReadFile(path)
	if r := run(nil, append([]string{"verify", path}, flags(dev)...)...); r.e != nil {
		t.Fatal(r.e)
	}
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, append([]string{"info", path}, flags(dev)...)...); !errors.Is(r.e, theca.ErrRollback) {
		t.Fatalf("rolled-back copy after a rebind: %v", r.e)
	}

	// A different TPM (cleared, replaced): the index does not exist there.
	other := startSwtpmDevice(t)
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, append([]string{"info", path}, flags(other)...)...); !errors.Is(r.e, nvcounter.ErrNoCounter) {
		t.Fatalf("on another TPM: %v", r.e)
	}
	if r := run(nil, append([]string{"counter", "rebind", path}, flags(other)...)...); r.e != nil {
		t.Fatalf("rebind on the other TPM: %v", r.e)
	}
	if r := run(nil, append([]string{"info", path}, flags(other)...)...); r.e != nil {
		t.Fatalf("open on the other TPM after the rebind: %v", r.e)
	}
}

// The real constructors report a TPM that cannot be reached.
func TestRealCounterConstructorsRefuse(t *testing.T) {
	o := nvcounter.Options{Device: filepath.Join(t.TempDir(), "no-such-device"), Handle: 1}
	if c, err := createCounter(o); err == nil || c != nil {
		t.Fatalf("create: %v %v", c, err)
	}
	if c, err := openCounter(o); err == nil || c != nil {
		t.Fatalf("open: %v %v", c, err)
	}
	if removed, err := removeCounter(o); err == nil || removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
}

// A rebind of a HEALTHY counter deletes it: a copy taken just before is
// refused. Without that, the old counter stays at the value the copy is bound
// to, and the copy opens with no flag: a silent rollback to before the rebind.
func TestCounterTPMSwtpmRebindOfAHealthyCounter(t *testing.T) {
	dev := startSwtpmDevice(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	flags := []string{"--password-file", pw, "--counter", "tpm", "--tpm-device", dev}
	if r := run(nil, append([]string{"create", path, "--size", "1M"}, flags...)...); r.e != nil {
		t.Fatal(r.e)
	}
	before, err := os.ReadFile(path) // the copy an attacker took just before the rebind
	if err != nil {
		t.Fatal(err)
	}
	r := run(nil, append([]string{"counter", "rebind", path}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "has been DELETED") {
		t.Fatalf("rebind: %v %q", r.e, r.err)
	}
	if r := run(nil, append([]string{"info", path}, flags...)...); r.e != nil {
		t.Fatalf("the rebound container: %v", r.e)
	}
	cur, _ := os.ReadFile(path)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, append([]string{"info", path}, flags...)...); r.e == nil {
		t.Fatal("a copy from before the rebind opened: the rebind did not delete the old counter")
	}
	if err := os.WriteFile(path, cur, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(nil, append([]string{"info", path}, flags...)...); r.e != nil {
		t.Fatalf("the current copy: %v", r.e)
	}
}

// The real nvcounter behind the flags, on a software TPM.
func TestCounterTPMSwtpm(t *testing.T) {
	dev := startSwtpmDevice(t)
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "correct horse\n", 0o600)
	auth := secretFile(t, dir, "auth", "index secret\n", 0o600)
	path := filepath.Join(dir, "c.theca")
	flags := []string{"--counter", "tpm", "--tpm-device", dev, "--tpm-auth-file", auth}
	r := run(nil, append([]string{"create", path, "--size", "1M", "--password-file", pw}, flags...)...)
	if r.e != nil || !strings.Contains(r.err, "TPM NV index 0x01500000") {
		t.Fatalf("create: %v %q", r.e, r.err)
	}
	r = run(nil, append([]string{"info", path, "--password-file", pw}, flags...)...)
	if r.e != nil || !strings.Contains(r.out, "rollback protected: true") {
		t.Fatalf("info: %v %q %q", r.e, r.out, r.err)
	}
	older, _ := os.ReadFile(path)
	if r := run(nil, append([]string{"verify", path, "--password-file", pw}, flags...)...); r.e != nil {
		t.Fatal(r.e)
	}
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(nil, append([]string{"info", path, "--password-file", pw}, flags...)...)
	if !errors.Is(r.e, theca.ErrRollback) {
		t.Fatalf("rolled-back copy on a real TPM: %v", r.e)
	}
}
