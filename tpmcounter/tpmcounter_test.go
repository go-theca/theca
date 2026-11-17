package tpmcounter

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-tpm2/tpm2"

	"github.com/go-theca/theca"
)

// The counter is a theca.Counter.
var _ theca.Counter = (*Counter)(nil)

// fakeTPM is an in-memory NV counter store.
type fakeTPM struct {
	pubs    map[uint32]tpm2.NVPublic
	vals    map[uint32]uint64
	written map[uint32]bool
	fail    map[string]error
	always  bool // NVReadPublic reports every handle as taken
	closeEr error
	device  string
}

func newFake() *fakeTPM {
	return &fakeTPM{pubs: map[uint32]tpm2.NVPublic{}, vals: map[uint32]uint64{},
		written: map[uint32]bool{}, fail: map[string]error{}}
}

func (f *fakeTPM) NVDefineCounter(owner, idx []byte, h uint32) ([]byte, error) {
	if e := f.fail["define"]; e != nil {
		return nil, e
	}
	f.pubs[h] = tpm2.NVPublic{Index: h, NameAlg: 0x0B, Attributes: tpm2.CounterAttributes, DataSize: 8}
	return []byte{0, 0x0B, byte(h)}, nil
}

func (f *fakeTPM) NVReadPublic(h uint32) (tpm2.NVPublic, []byte, error) {
	if e := f.fail["readpublic"]; e != nil {
		return tpm2.NVPublic{}, nil, e
	}
	p, ok := f.pubs[h]
	if f.always {
		return p, nil, nil
	}
	if !ok {
		return tpm2.NVPublic{}, nil, &tpm2.TPMError{CC: 0x169, RC: 0x18B}
	}
	if f.written[h] {
		p.Attributes |= tpm2.NVWritten
	}
	// The Name covers the WRITTEN attribute: it changes at the first increment.
	return p, []byte{0, 0x0B, byte(h), byte(p.Attributes >> 29 & 1)}, nil
}

func (f *fakeTPM) NVIncrementAuth(hh uint32, auth []byte, h uint32) error {
	if e := f.fail["increment"]; e != nil {
		return e
	}
	f.vals[h]++
	f.written[h] = true
	return nil
}

func (f *fakeTPM) NVReadCounter(auth []byte, h uint32) (uint64, error) {
	if e := f.fail["read"]; e != nil {
		return 0, e
	}
	return f.vals[h], nil
}

func (f *fakeTPM) NVUndefineSpaceAuth(owner []byte, h uint32) error {
	if e := f.fail["undefine"]; e != nil {
		return e
	}
	delete(f.pubs, h)
	return nil
}

// use installs f as the TPM behind connect, for the test's duration.
func use(t *testing.T, f *fakeTPM) {
	t.Helper()
	old, oldOS := connect, goos
	t.Cleanup(func() { connect, goos = old, oldOS })
	goos = "linux"
	connect = func(device string) (nvTPM, func() error, error) {
		f.device = device
		if e := f.fail["connect"]; e != nil {
			return nil, nil, e
		}
		return f, func() error { return f.closeEr }, nil
	}
}

var boom = errors.New("boom")

func TestCreateOpenIncrementRead(t *testing.T) {
	f := newFake()
	use(t, f)
	f.pubs[First] = tpm2.NVPublic{} // taken
	f.pubs[First+1] = tpm2.NVPublic{}
	c, err := Create(Options{Auth: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	if c.Handle() != First+2 || len(c.Name()) == 0 || f.device != DefaultLinuxDevice {
		t.Fatalf("handle %#x name %x device %q", c.Handle(), c.Name(), f.device)
	}
	before := string(c.Name())
	if err := c.Increment(); err != nil {
		t.Fatal(err)
	}
	if string(c.Name()) == before {
		t.Fatal("the Name was not refreshed after the first increment")
	}
	if v, err := c.Read(); err != nil || v != 1 {
		t.Fatalf("read %d %v", v, err)
	}
	o, err := Open(Options{Handle: c.Handle(), Auth: []byte("a"), Device: "/dev/x"})
	if err != nil || string(o.Name()) != string(c.Name()) || f.device != "/dev/x" {
		t.Fatalf("open: %v %x", err, o)
	}
	if err := c.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.pubs[c.Handle()]; ok {
		t.Fatal("not destroyed")
	}
}

func TestCreateExplicitHandle(t *testing.T) {
	f := newFake()
	use(t, f)
	c, err := Create(Options{Handle: 0x01500777})
	if err != nil || c.Handle() != 0x01500777 {
		t.Fatalf("%v %v", c, err)
	}
}

func TestCreateErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	if _, err := Create(Options{Auth: make([]byte, 33)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("auth: %v", err)
	}
	if _, err := Create(Options{OwnerAuth: make([]byte, 33)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("owner auth: %v", err)
	}
	f.fail["define"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("define: %v", err)
	}
	delete(f.fail, "define")
	f.fail["readpublic"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("probe: %v", err)
	}
	delete(f.fail, "readpublic")
	f.always = true
	if _, err := Create(Options{}); !errors.Is(err, ErrNoFreeHandle) {
		t.Fatalf("full: %v", err)
	}
	f.always = false
	f.fail["connect"] = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("connect: %v", err)
	}
	delete(f.fail, "connect")
	f.closeEr = boom
	if _, err := Create(Options{}); !errors.Is(err, boom) {
		t.Fatalf("close: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	if _, err := Open(Options{Handle: 1, Auth: make([]byte, 40)}); !errors.Is(err, ErrAuthTooLong) {
		t.Fatalf("auth: %v", err)
	}
	if _, err := Open(Options{Handle: First}); err == nil {
		t.Fatal("open of an undefined handle")
	}
	f.pubs[First] = tpm2.NVPublic{Attributes: 0x00060006, DataSize: 32} // an ordinary index
	if _, err := Open(Options{Handle: First}); !errors.Is(err, ErrNotCounter) {
		t.Fatalf("ordinary index: %v", err)
	}
	f.pubs[First] = tpm2.NVPublic{Attributes: tpm2.CounterAttributes, DataSize: 4}
	if _, err := Open(Options{Handle: First}); !errors.Is(err, ErrNotCounter) {
		t.Fatalf("wrong size: %v", err)
	}
}

func TestOperationErrors(t *testing.T) {
	f := newFake()
	use(t, f)
	c, err := Create(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"read":       func() error { _, e := c.Read(); return e },
		"increment":  c.Increment,
		"readpublic": c.Increment, // the Name refresh after the increment
		"undefine":   c.Destroy,
	} {
		f.fail[name] = boom
		if err := call(); !errors.Is(err, boom) {
			t.Fatalf("%s: %v", name, err)
		}
		delete(f.fail, name)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	f := newFake()
	use(t, f)
	for _, os := range []string{"darwin", "windows"} {
		goos = os
		if _, err := Create(Options{}); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s: %v", os, err)
		}
		// An explicit device is honored anywhere.
		if _, err := Create(Options{Device: "unix:/x"}); err != nil {
			t.Fatalf("%s with a device: %v", os, err)
		}
	}
}

// The real connect: a character device path, and a unix socket.
func TestConnect(t *testing.T) {
	if _, _, err := connect(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing device opened")
	}
	file := filepath.Join(t.TempDir(), "tpm")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tp, closeFn, err := connect(file)
	if err != nil || tp == nil || closeFn() != nil {
		t.Fatalf("file device: %v", err)
	}
	dir, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	if _, _, err := connect("unix:" + sock); err == nil {
		t.Fatal("a missing socket connected")
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tp, closeFn, err = connect("unix:" + sock)
	if err != nil || tp == nil || closeFn() != nil {
		t.Fatalf("unix device: %v", err)
	}
}
