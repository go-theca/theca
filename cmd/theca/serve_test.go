package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-fileshare/automount"
	exfat "github.com/go-filesystems/exfat"
	"github.com/go-filesystems/smb"

	"github.com/go-theca/theca"
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
	if cr.User != shareUser || len(cr.Password) < 30 || !strings.HasPrefix(cr.URL, "smb://127.0.0.1:") || !strings.HasSuffix(cr.URL, "/theca") {
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
	// localhost is a loopback name.
	if err := loopbackOnly("localhost:0"); err != nil {
		t.Fatal(err)
	}
}

func TestServeStopsOnAFailure(t *testing.T) {
	noSignals(t)
	dir, path, pw := exfatContainer(t)
	boom := errors.New("boom")

	// The commit failing stops the server and reports it.
	savedSync := syncContainer
	t.Cleanup(func() { syncContainer = savedSync })
	syncContainer = func(*theca.Container) error { return boom }
	r := runCtx(context.Background(), "serve", path, "--password-file", pw, "--credentials-out", filepath.Join(dir, "c1"), "--sync", "1ms")
	if !errors.Is(r.e, boom) {
		t.Fatalf("sync failure: %v", r.e)
	}
	syncContainer = savedSync

	// The server failing stops it too.
	savedServe := serveSMB
	t.Cleanup(func() { serveSMB = savedServe })
	serveSMB = func(*smb.Server, net.Listener) error { return boom }
	r = runCtx(context.Background(), "serve", path, "--password-file", pw, "--credentials-out", filepath.Join(dir, "c2"))
	if !errors.Is(r.e, boom) {
		t.Fatalf("server failure: %v", r.e)
	}
}

// fakeMount records what serve asked of the OS mount.
type fakeMount struct {
	mounted   chan struct{}
	url, user string
	pwLen     int
	unmounted bool
	unmountTo error
}

func (m *fakeMount) Path() string { return "/Volumes/theca" }
func (m *fakeMount) Unmount(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err() // the stop context must not reach the unmount
	}
	m.unmounted = true
	return m.unmountTo
}

func withFakeMount(t *testing.T, fm *fakeMount, mountErr error) {
	t.Helper()
	saved := mountShare
	t.Cleanup(func() { mountShare = saved })
	mountShare = func(ctx context.Context, u *url.URL, user, password string) (mounted, error) {
		fm.url, fm.user, fm.pwLen = u.String(), user, len(password)
		close(fm.mounted)
		if mountErr != nil {
			return nil, mountErr
		}
		return fm, nil
	}
}

func TestServeMount(t *testing.T) {
	noSignals(t)
	_, path, pw := exfatContainer(t)
	fm := &fakeMount{mounted: make(chan struct{})}
	withFakeMount(t, fm, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() { done <- runCtx(ctx, "serve", path, "--password-file", pw, "--mount", "--sync", "10ms") }()
	<-fm.mounted
	time.Sleep(30 * time.Millisecond)
	cancel()
	r := <-done
	if r.e != nil {
		t.Fatalf("serve --mount: %v %q", r.e, r.err)
	}
	if !strings.HasPrefix(fm.url, "smb://127.0.0.1:") || !strings.HasSuffix(fm.url, "/theca") || fm.user != shareUser || fm.pwLen < 30 {
		t.Fatalf("mounted %q as %q (password %d chars)", fm.url, fm.user, fm.pwLen)
	}
	if !fm.unmounted {
		t.Fatal("not unmounted at stop")
	}
	if !strings.Contains(r.out, "mounted at /Volumes/theca") || strings.Contains(r.out, "credentials in") {
		t.Fatalf("output %q", r.out)
	}
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("verify after serve --mount: %v", r.e)
	}
}

func TestServeMountFailures(t *testing.T) {
	noSignals(t)
	dir, path, pw := exfatContainer(t)
	boom := errors.New("boom")

	// A mount that fails stops serve, removes the credentials file, and says so.
	creds := filepath.Join(dir, "creds.json")
	withFakeMount(t, &fakeMount{mounted: make(chan struct{})}, boom)
	r := runCtx(context.Background(), "serve", path, "--password-file", pw, "--mount", "--credentials-out", creds)
	if !errors.Is(r.e, boom) || !strings.Contains(r.e.Error(), "mounting smb://127.0.0.1:") {
		t.Fatalf("mount failure: %v", r.e)
	}
	if _, err := os.Stat(creds); !os.IsNotExist(err) {
		t.Fatal("credentials file left behind")
	}

	// An unmount that fails is reported, and the container is still closed.
	fm := &fakeMount{mounted: make(chan struct{}), unmountTo: boom}
	withFakeMount(t, fm, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() { done <- runCtx(ctx, "serve", path, "--password-file", pw, "--mount") }()
	<-fm.mounted
	cancel()
	r = <-done
	if !errors.Is(r.e, boom) || !strings.Contains(r.e.Error(), "unmounting /Volumes/theca") {
		t.Fatalf("unmount failure: %v", r.e)
	}
	if r := run(nil, "verify", path, "--password-file", pw); r.e != nil {
		t.Fatalf("verify after a failed unmount: %v", r.e)
	}
}

func TestMountShareDefault(t *testing.T) {
	// The real seam reaches automount: a URL it refuses comes back as an
	// error and a nil interface, never a typed nil.
	m, err := mountShare(context.Background(), &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/x"}, "u", "p")
	if err == nil || m != nil {
		t.Fatalf("http URL: %v %v", m, err)
	}
	if m, err := asMounted(&automount.Mounted{}, nil); err != nil || m == nil {
		t.Fatalf("asMounted: %v %v", m, err)
	}
}

func TestStopSignalsDefault(t *testing.T) {
	ctx, stop := stopSignals(context.Background())
	stop()
	<-ctx.Done()
}
