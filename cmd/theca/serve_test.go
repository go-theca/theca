package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	exfat "github.com/go-filesystems/exfat"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/share"
)

// runCtx is run with a context, so a test can stop a serve.
func runCtx(ctx context.Context, args ...string) result {
	c := RootCmd()
	var o, e bytes.Buffer
	c.SetArgs(args)
	c.SetOut(&o)
	c.SetErr(&e)
	err := c.ExecuteContext(ctx)
	return result{o.String(), e.String(), err}
}

// noSignals makes serve stop only when its context is cancelled.
func noSignals(t *testing.T) {
	t.Helper()
	saved := stopSignals
	t.Cleanup(func() { stopSignals = saved })
	stopSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(ctx)
	}
}

// exfatContainer creates a 4 MiB container formatted with exFAT.
func exfatContainer(t *testing.T) (dir, path, pw string) {
	t.Helper()
	dir = t.TempDir()
	pw = secretFile(t, dir, "pw", "correct horse", 0o600)
	path = filepath.Join(dir, "c.theca")
	if r := run(nil, "create", path, "--size", "4M", "--fs", "exfat", "--password-file", pw); r.e != nil {
		t.Fatalf("create --fs exfat: %v %s", r.e, r.err)
	}
	return
}

// waitFile waits for path to appear, as a client of serve would.
func waitFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return nil
}

func TestCreateFormatsExFAT(t *testing.T) {
	_, path, _ := exfatContainer(t)
	// The filesystem is there and takes a file, through the container.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := theca.Open(context.Background(), theca.FileBacking{File: f}, theca.Unlock{Password: []byte("correct horse")}, theca.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := exfat.OpenReader(c, c.Size())
	if err != nil {
		t.Fatalf("no exFAT inside: %v", err)
	}
	if err := fsys.WriteFile("/hello.txt", []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys.Close()
	closeBoth(c, f, nil)
	// Reopened: the file survived the commit.
	f, _ = os.OpenFile(path, os.O_RDWR, 0)
	c, err = theca.Open(context.Background(), theca.FileBacking{File: f}, theca.Unlock{Password: []byte("correct horse")}, theca.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fsys, _ = exfat.OpenReader(c, c.Size())
	if b, err := fsys.ReadFile("/hello.txt"); err != nil || string(b) != "hi" {
		t.Fatalf("after reopen: %q %v", b, err)
	}
	fsys.Close()
	closeBoth(c, f, nil)
}

func TestCreateFSRefusals(t *testing.T) {
	dir := t.TempDir()
	pw := secretFile(t, dir, "pw", "x", 0o600)
	if r := run(nil, "create", filepath.Join(dir, "a"), "--size", "4M", "--fs", "ntfs", "--password-file", pw); r.e == nil {
		t.Fatal("--fs ntfs accepted")
	}
	// Too small for exFAT: the half-made container is removed.
	small := filepath.Join(dir, "small")
	if r := run(nil, "create", small, "--size", "4K", "--fs", "exfat", "--password-file", pw); r.e == nil {
		t.Fatal("a 4 KiB exFAT accepted")
	}
	if _, err := os.Stat(small); !os.IsNotExist(err) {
		t.Fatalf("half-made container left: %v", err)
	}
}

func TestServeLifecycle(t *testing.T) {
	noSignals(t)
	dir, path, pw := exfatContainer(t)
	creds := filepath.Join(dir, "creds.json")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() {
		done <- runCtx(ctx, "serve", path, "--password-file", pw, "--credentials-out", creds, "--sync", "10ms")
	}()
	var cr credentials
	if err := json.Unmarshal(waitFile(t, creds), &cr); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(creds); st.Mode().Perm() != 0o600 {
		t.Fatalf("credentials mode %04o", st.Mode().Perm())
	}
	if !strings.HasPrefix(cr.User, share.UserPrefix) || len(cr.User) != len(share.UserPrefix)+8 || len(cr.Password) < 30 || !strings.HasPrefix(cr.URL, "smb://127.0.0.1:") || !strings.HasSuffix(cr.URL, "/theca") {
		t.Fatalf("credentials %+v", cr)
	}
	// The port answers.
	host := strings.TrimSuffix(strings.TrimPrefix(cr.URL, "smb://"), "/theca")
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond) // let a few syncs run
	cancel()
	r := <-done
	if r.e != nil || !strings.Contains(r.out, "serving smb://127.0.0.1:") {
		t.Fatalf("serve: %v %q %q", r.e, r.out, r.err)
	}
	if _, err := os.Stat(creds); !os.IsNotExist(err) {
		t.Fatal("credentials file left behind")
	}
	// The container is intact and still holds its filesystem.
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("verify after serve: %v", r.e)
	}
}

func TestServeRefusals(t *testing.T) {
	noSignals(t)
	dir, path, pw := exfatContainer(t)
	creds := filepath.Join(dir, "creds.json")
	_, raw, rawPW, _ := newContainer(t) // a raw volume: no exFAT
	existing := secretFile(t, dir, "exists", "x", 0o600)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	for name, args := range map[string][]string{
		"neither mount nor credentials-out": {"serve", path, "--password-file", pw},
		"network address":                   {"serve", path, "--password-file", pw, "--credentials-out", creds, "--addr", "0.0.0.0:0"},
		"hostname":                          {"serve", path, "--password-file", pw, "--credentials-out", creds, "--addr", "example.org:0"},
		"bad address":                       {"serve", path, "--password-file", pw, "--credentials-out", creds, "--addr", "nope"},
		"zero sync":                         {"serve", path, "--password-file", pw, "--credentials-out", creds, "--sync", "0s"},
		"wrong password":                    {"serve", path, "--password-file", secretFile(t, dir, "bad", "nope", 0o600), "--credentials-out", creds},
		"raw volume":                        {"serve", raw, "--password-file", rawPW, "--credentials-out", creds},
		"port in use":                       {"serve", path, "--password-file", pw, "--credentials-out", creds, "--addr", busy.Addr().String()},
		"credentials exist":                 {"serve", path, "--password-file", pw, "--credentials-out", existing},
		"bad share name":                    {"serve", path, "--password-file", pw, "--credentials-out", creds, "--share", ""},
	} {
		if r := runCtx(context.Background(), args...); r.e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(creds); !os.IsNotExist(err) {
		t.Fatal("a refused serve left a credentials file")
	}
	// The hint for a container with no filesystem names the fix.
	r := runCtx(context.Background(), "serve", raw, "--password-file", rawPW, "--credentials-out", creds)
	if !errors.Is(r.e, share.ErrNoFilesystem) || !strings.Contains(r.e.Error(), "--fs exfat") {
		t.Fatalf("raw volume: %v", r.e)
	}
}

// fakeShare stands in for a running share.
type fakeShare struct {
	mount   string
	done    chan struct{}
	stopErr error
	stopped bool
}

func (f *fakeShare) Addr() string          { return "0.0.0.0:4455" }
func (f *fakeShare) URL() string           { return "smb://127.0.0.1:1/theca" }
func (f *fakeShare) User() string          { return "theca" }
func (f *fakeShare) Password() string      { return "secret" }
func (f *fakeShare) MountPath() string     { return f.mount }
func (f *fakeShare) Done() <-chan struct{} { return f.done }
func (f *fakeShare) Stop() error           { f.stopped = true; return f.stopErr }

func withFakeShare(t *testing.T, fs *fakeShare, startErr error) {
	t.Helper()
	saved := startShare
	t.Cleanup(func() { startShare = saved })
	startShare = func(context.Context, *theca.Container, share.Options) (sharer, error) {
		if startErr != nil {
			return nil, startErr
		}
		return fs, nil
	}
}

func TestServeMountOutput(t *testing.T) {
	noSignals(t)
	_, path, pw := exfatContainer(t)
	fs := &fakeShare{mount: "/Volumes/theca", done: make(chan struct{})}
	close(fs.done)
	withFakeShare(t, fs, nil)
	r := runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount")
	if r.e != nil {
		t.Fatalf("serve --mount: %v %q", r.e, r.err)
	}
	if !fs.stopped || !strings.Contains(r.out, "mounted at /Volumes/theca") || strings.Contains(r.out, "credentials in") {
		t.Fatalf("stopped=%v output %q", fs.stopped, r.out)
	}
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("verify after serve --mount: %v", r.e)
	}
}

func TestServeShareFailures(t *testing.T) {
	noSignals(t)
	dir, path, pw := exfatContainer(t)
	boom := errors.New("boom")

	// A share that fails to start is reported, and the container is closed.
	withFakeShare(t, nil, boom)
	creds := filepath.Join(dir, "creds.json")
	r := runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount", "--credentials-out", creds)
	if !errors.Is(r.e, boom) {
		t.Fatalf("start failure: %v", r.e)
	}
	if _, err := os.Stat(creds); !os.IsNotExist(err) {
		t.Fatal("credentials file left behind")
	}

	// A share that ends with an error reports it from Stop.
	fs := &fakeShare{done: make(chan struct{}), stopErr: boom}
	close(fs.done)
	withFakeShare(t, fs, nil)
	r = runCtx(context.Background(), "serve", path, "--password-file", pw, "--credentials-out", creds)
	if !errors.Is(r.e, boom) {
		t.Fatalf("stop failure: %v", r.e)
	}

	// Credentials that cannot be written stop the share.
	fs = &fakeShare{done: make(chan struct{})}
	withFakeShare(t, fs, nil)
	existing := secretFile(t, dir, "exists", "x", 0o600)
	r = runCtx(context.Background(), "serve", path, "--password-file", pw, "--credentials-out", existing)
	if r.e == nil || !fs.stopped {
		t.Fatalf("credentials exist: %v stopped=%v", r.e, fs.stopped)
	}
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("verify after failures: %v", r.e)
	}
}

func TestServeNetwork(t *testing.T) {
	noSignals(t)
	_, path, pw := exfatContainer(t)
	// Without --network a non-loopback address is refused, naming the flag.
	r := runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount", "--addr", "0.0.0.0:4455")
	if r.e == nil || !strings.Contains(r.e.Error(), "--network") {
		t.Fatalf("0.0.0.0 without --network: %v", r.e)
	}
	// With it, the options say so and the warning is on stderr, not stdout.
	var got share.Options
	saved := startShare
	t.Cleanup(func() { startShare = saved })
	fs := &fakeShare{done: make(chan struct{})}
	close(fs.done)
	startShare = func(_ context.Context, _ *theca.Container, o share.Options) (sharer, error) {
		got = o
		return fs, nil
	}
	r = runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount", "--network", "--addr", "0.0.0.0:4455")
	if r.e != nil || !got.Network || got.Addr != "0.0.0.0:4455" {
		t.Fatalf("serve --network: %v %+v", r.e, got)
	}
	if !strings.Contains(r.err, "warning: --network: listening on 0.0.0.0:4455") || strings.Contains(r.out, "warning") {
		t.Fatalf("stderr %q stdout %q", r.err, r.out)
	}
	// Loopback with no --network: no warning.
	r = runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount")
	if got.Network || strings.Contains(r.err, "warning: --network") {
		t.Fatalf("a plain serve warned: %q", r.err)
	}
}

func TestStartShareDefault(t *testing.T) {
	// The real seam reaches share.Start: a refusal comes back as an error and
	// a nil interface, never a typed nil.
	sh, err := startShare(context.Background(), nil, share.Options{Addr: "0.0.0.0:0", Name: "theca", Sync: time.Second})
	if err == nil || sh != nil {
		t.Fatalf("network address: %v %v", sh, err)
	}
}

func TestStopSignalsDefault(t *testing.T) {
	ctx, stop := stopSignals(context.Background())
	stop()
	<-ctx.Done()
}
