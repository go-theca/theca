package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/tpmcounter"
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
	created    []tpmcounter.Options
	opened     []tpmcounter.Options
	createErr  error
	openErr    error
	failIncAt1 bool
}

func installFakeTPM(t *testing.T) *fakeTPM {
	t.Helper()
	f := &fakeTPM{}
	sc, so := createCounter, openCounter
	t.Cleanup(func() { createCounter, openCounter = sc, so })
	createCounter = func(o tpmcounter.Options) (tpmCounter, error) {
		o.Auth, o.OwnerAuth = append([]byte(nil), o.Auth...), append([]byte(nil), o.OwnerAuth...) // the CLI wipes its copies
		f.created = append(f.created, o)
		if f.createErr != nil {
			return nil, f.createErr
		}
		h := o.Handle
		if h == 0 {
			h = 0x01500000
		}
		f.ctr = &fakeCounter{h: h, v: 40}
		if f.failIncAt1 {
			f.ctr.incErr = errors.New("increment refused")
		}
		return f.ctr, nil
	}
	openCounter = func(o tpmcounter.Options) (theca.Counter, error) {
		o.Auth, o.OwnerAuth = append([]byte(nil), o.Auth...), append([]byte(nil), o.OwnerAuth...)
		f.opened = append(f.opened, o)
		if f.openErr != nil {
			return nil, f.openErr
		}
		return f.ctr, nil
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
	f.createErr = tpmcounter.ErrUnsupported
	if r := create("--counter", "tpm"); !errors.Is(r.e, tpmcounter.ErrUnsupported) {
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
	f.openErr = tpmcounter.ErrNotCounter
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "tpm"); !errors.Is(r.e, tpmcounter.ErrNotCounter) {
		t.Fatalf("open: %v", r.e)
	}
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "tpm", "--tpm-auth-file", filepath.Join(dir, "none")); r.e == nil {
		t.Fatal("an unreadable authValue file was accepted")
	}
	if r := run(nil, "info", path, "--password-file", pw, "--counter", "sgx"); r.e == nil {
		t.Fatal("an unknown counter was accepted")
	}
}

// The real constructors report a TPM that cannot be reached.
func TestRealCounterConstructorsRefuse(t *testing.T) {
	o := tpmcounter.Options{Device: filepath.Join(t.TempDir(), "no-such-device"), Handle: 1}
	if c, err := createCounter(o); err == nil || c != nil {
		t.Fatalf("create: %v %v", c, err)
	}
	if c, err := openCounter(o); err == nil || c != nil {
		t.Fatalf("open: %v %v", c, err)
	}
}

// The real tpmcounter behind the flags, on a software TPM.
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
