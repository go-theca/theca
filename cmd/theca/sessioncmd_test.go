package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/profile"
	"github.com/go-theca/theca/session"
	"github.com/go-theca/theca/share"
)

// init makes the test binary double as the background process: spawnDaemon runs
// this binary with THECA_FAKE_DAEMON set, and it answers on descriptor 3 the way
// `theca _serve` does.
func init() {
	mode := os.Getenv("THECA_FAKE_DAEMON")
	if mode == "" {
		return
	}
	ready := os.NewFile(3, "ready")
	switch mode {
	case "ok":
		session.Report(ready, session.Response{OK: true, Info: &session.Info{Name: os.Args[2], Mount: "/Volumes/THECA"}})
	case "err":
		session.Report(ready, session.Response{Error: "wrong password"})
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

// sessionEnv points every seam of open/close/status at a private world: its own
// profile file, its own short socket directory, a secret manager that knows one
// entry, a lock channel the test drives.
type sessionEnv struct {
	store profile.Store
	dir   string // socket directory
	lock  chan string
}

func newSessionEnv(t *testing.T) *sessionEnv {
	t.Helper()
	noSignals(t)
	d, err := os.MkdirTemp("", "tc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	e := &sessionEnv{store: profile.Store{Path: filepath.Join(t.TempDir(), "containers.toml")}, dir: d, lock: make(chan string, 1)}
	sPS, sSP, sWL, sDT, sRR, sRF, sSD := profileStore, socketPath, watchLock, detach, readRef, readyFile, startDaemon
	t.Cleanup(func() {
		profileStore, socketPath, watchLock, detach, readRef, readyFile, startDaemon = sPS, sSP, sWL, sDT, sRR, sRF, sSD
	})
	profileStore = func() (profile.Store, error) { return e.store, nil }
	socketPath = func(name string) (string, error) { return filepath.Join(e.dir, name+".sock"), nil }
	watchLock = func(context.Context) (<-chan string, error) { return e.lock, nil }
	detach = func() error { return nil }
	readRef = func(_ context.Context, ref string) ([]byte, error) {
		if ref == "keychain:theca/bio" {
			return []byte("correct horse"), nil
		}
		return nil, errors.New("no such entry")
	}
	return e
}

// inProc starts the background process inside the test, and waits for its report.
func (e *sessionEnv) inProc(t *testing.T, name string) (done chan result) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyFile = func() *os.File { return w }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done = make(chan result, 1)
	go func() { done <- runCtx(ctx, "_serve", name) }()
	if _, err := session.DecodeResponse(r); err != nil {
		t.Fatalf("no report: %v", err)
	}
	r.Close()
	return done
}

func (e *sessionEnv) add(t *testing.T, name, path string, extra ...string) {
	t.Helper()
	args := append([]string{"profile", "add", name, path, "--password-from", "keychain:theca/bio"}, extra...)
	if r := run(nil, args...); r.e != nil {
		t.Fatalf("profile add: %v %s", r.e, r.err)
	}
}

func TestProfileCommands(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path, "--device", "bio", "--counter", "tpm", "--tpm-device", "unix:/s", "--close-on-lock=false")
	r := run(nil, "profile", "list")
	if r.e != nil || !strings.Contains(r.out, "bio") || !strings.Contains(r.out, "keychain:theca/bio") || !strings.Contains(r.out, "false") {
		t.Fatalf("list: %v %q", r.e, r.out)
	}
	st, _ := os.Stat(e.store.Path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	b, _ := os.ReadFile(e.store.Path)
	if strings.Contains(string(b), "correct horse") {
		t.Fatal("a secret reached the profile file")
	}
	// A second add, a key without a device name, a terminal password.
	if r := run(nil, "profile", "add", "bio", path); r.e == nil {
		t.Fatal("duplicate accepted")
	}
	if r := run(nil, "profile", "add", "bio", path, "--replace", "--fido2"); r.e != nil {
		t.Fatal(r.e)
	}
	r = run(nil, "profile", "list")
	if !strings.Contains(r.out, "(terminal)") || !strings.Contains(r.out, "yes") {
		t.Fatalf("list: %q", r.out)
	}
	run(nil, "profile", "add", "plain", path)
	if r := run(nil, "profile", "list"); !strings.Contains(r.out, "-") {
		t.Fatal(r.out)
	}
	// Refusals.
	for _, args := range [][]string{
		{"profile", "add", "x", path, "--password-from", "file:/etc/passwd"},
		{"profile", "add", "x", path, "--password-from", "nonsense"},
		{"profile", "add", "bad name", path},
		{"profile", "add", "x", filepath.Join(filepath.Dir(path), "missing")},
		{"profile", "add", "x", filepath.Dir(path)},
		{"profile", "remove", "ghost"},
	} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if r := run(nil, "profile", "remove", "plain"); r.e != nil || !strings.Contains(r.out, "removed") {
		t.Fatal(r.e, r.out)
	}
}

func TestProfileStoreErrors(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	boom := errors.New("no config dir")
	profileStore = func() (profile.Store, error) { return profile.Store{}, boom }
	for _, args := range [][]string{
		{"profile", "add", "x", path}, {"profile", "list"}, {"profile", "remove", "x"},
		{"open", "x"}, {"status"}, {"_serve", "x"},
	} {
		_, w, _ := os.Pipe()
		readyFile = func() *os.File { return w }
		if r := run(nil, args...); !errors.Is(r.e, boom) {
			t.Errorf("%v: %v", args, r.e)
		}
	}
	// A profile file that cannot be read (mode) fails list, status, add.
	profileStore = func() (profile.Store, error) { return e.store, nil }
	os.WriteFile(e.store.Path, nil, 0o644)
	for _, args := range [][]string{{"profile", "add", "x", path}, {"profile", "list"}, {"status"}} {
		if r := run(nil, args...); r.e == nil {
			t.Errorf("%v: world-readable profile file accepted", args)
		}
	}
}

func TestDefaultProfileStore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	st, err := profileStore()
	if err != nil || !strings.HasSuffix(st.Path, filepath.Join("theca", "containers.toml")) {
		t.Fatal(st.Path, err)
	}
}

func TestOpenStatusClose(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path)
	fs := &fakeShare{mount: "/Volumes/THECA", done: make(chan struct{})}
	var opts share.Options
	saved := startShare
	t.Cleanup(func() { startShare = saved })
	startShare = func(_ context.Context, _ *theca.Container, o share.Options) (sharer, error) { opts = o; return fs, nil }
	var daemonDone chan result
	startDaemon = func(_ context.Context, name string, _ *os.File) (session.Info, error) {
		daemonDone = e.inProc(t, name)
		sp, _ := socketPath(name)
		return session.Status(context.Background(), sp)
	}
	r := run(nil, "open", "bio")
	if r.e != nil || !strings.Contains(r.out, "mounted at /Volumes/THECA") || !strings.Contains(r.out, "theca close bio") {
		t.Fatalf("open: %v %q %q", r.e, r.out, r.err)
	}
	if !opts.Mount || opts.Addr != "127.0.0.1:0" || opts.Name != "theca" || opts.Network || opts.Sync != profile.DefaultSync {
		t.Fatalf("share options %+v", opts)
	}
	// A second open of the same container is refused, without a second unlock.
	if r := run(nil, "open", "bio"); r.e == nil || !strings.Contains(r.e.Error(), "already open") {
		t.Fatalf("second open: %v", r.e)
	}
	if r := run(nil, "status"); r.e != nil || !strings.Contains(r.out, "open") || !strings.Contains(r.out, "/Volumes/THECA") {
		t.Fatalf("status: %v %q", r.e, r.out)
	}
	if r := run(nil, "status", "other"); r.e != nil || strings.Contains(r.out, "bio") {
		t.Fatalf("status other: %q", r.out)
	}
	if r := run(nil, "close", "bio"); r.e != nil || !strings.Contains(r.out, "bio closed") {
		t.Fatalf("close: %v %q", r.e, r.out)
	}
	if res := <-daemonDone; res.e != nil || !fs.stopped {
		t.Fatalf("daemon: %v stopped=%v", res.e, fs.stopped)
	}
	if r := run(nil, "status"); !strings.Contains(r.out, "closed") {
		t.Fatalf("status after close: %q", r.out)
	}
	if r := run(nil, "close", "bio"); r.e == nil || !strings.Contains(r.e.Error(), "not open") {
		t.Fatalf("second close: %v", r.e)
	}
}

func TestSessionOpenRefusals(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path)
	if r := run(nil, "open", "ghost"); r.e == nil {
		t.Fatal("unknown profile opened")
	}
	startDaemon = func(context.Context, string, *os.File) (session.Info, error) {
		return session.Info{}, errors.New("wrong password")
	}
	if r := run(nil, "open", "bio"); r.e == nil || !strings.Contains(r.e.Error(), "wrong password") {
		t.Fatal(r.e)
	}
	boom := errors.New("bad socket dir")
	socketPath = func(string) (string, error) { return "", boom }
	for _, args := range [][]string{{"open", "bio"}, {"close", "bio"}, {"status"}} {
		if r := run(nil, args...); !errors.Is(r.e, boom) {
			t.Errorf("%v: %v", args, r.e)
		}
	}
}

func TestCloseReportsFailure(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path)
	fs := &fakeShare{mount: "/m", done: make(chan struct{}), stopErr: errors.New("unmount: busy")}
	withFakeShare(t, fs, nil)
	done := e.inProc(t, "bio")
	if r := run(nil, "close", "bio"); r.e == nil || !strings.Contains(r.e.Error(), "busy") {
		t.Fatalf("close: %v", r.e)
	}
	if res := <-done; res.e == nil {
		t.Fatal("daemon hid the stop error")
	}
}

func TestDaemonEnds(t *testing.T) {
	for _, how := range []string{"lock", "share", "signal"} {
		e := newSessionEnv(t)
		_, path, _ := exfatContainer(t)
		e.add(t, "bio", path)
		fs := &fakeShare{mount: "/m", done: make(chan struct{})}
		withFakeShare(t, fs, nil)
		r, w, _ := os.Pipe()
		readyFile = func() *os.File { return w }
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan result, 1)
		go func() { done <- runCtx(ctx, "_serve", "bio") }()
		if _, err := session.DecodeResponse(r); err != nil {
			t.Fatal(err)
		}
		r.Close()
		switch how {
		case "lock":
			e.lock <- "lock"
		case "share":
			close(fs.done)
		case "signal":
			cancel()
		}
		select {
		case res := <-done:
			if res.e != nil || !fs.stopped {
				t.Errorf("%s: %v stopped=%v", how, res.e, fs.stopped)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the daemon did not close the container", how)
		}
		cancel()
	}
}

func TestDaemonLockOptions(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	// close-on-lock = false: the lock channel is never watched, so a lock does nothing.
	e.add(t, "off", path, "--close-on-lock=false")
	fs := &fakeShare{mount: "/m", done: make(chan struct{})}
	withFakeShare(t, fs, nil)
	watched := false
	watchLock = func(context.Context) (<-chan string, error) { watched = true; return e.lock, nil }
	done := e.inProc(t, "off")
	e.lock <- "lock"
	time.Sleep(100 * time.Millisecond)
	if fs.stopped || watched {
		t.Fatal("watched the lock although the profile says not to")
	}
	sp0, _ := socketPath("off")
	if err := session.Close(context.Background(), sp0); err != nil {
		t.Fatal(err)
	}
	<-done
	// A system without a lock source warns and keeps running.
	e.add(t, "warn", path, "--share", "w")
	watchLock = func(context.Context) (<-chan string, error) { return nil, errors.New("no bus") }
	var errOut strings.Builder
	r, w, _ := os.Pipe()
	readyFile = func() *os.File { return w }
	c := RootCmd()
	c.SetArgs([]string{"_serve", "warn"})
	c.SetErr(&errOut)
	ctx, cancel := context.WithCancel(context.Background())
	fin := make(chan error, 1)
	go func() { fin <- c.ExecuteContext(ctx) }()
	if _, err := session.DecodeResponse(r); err != nil {
		t.Fatal(err)
	}
	sp, _ := socketPath("warn")
	if err := session.Close(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if err := <-fin; err != nil || !strings.Contains(errOut.String(), "close-on-lock: no bus") {
		t.Fatalf("%v %q", err, errOut.String())
	}
	cancel()
}

func TestDaemonFailures(t *testing.T) {
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path)
	report := func() (*os.File, *os.File) {
		r, w, _ := os.Pipe()
		readyFile = func() *os.File { return w }
		t.Cleanup(func() { r.Close() }) // a reader that is collected would turn the next write into EPIPE
		return r, w
	}
	// Not started by `theca open`.
	readyFile = func() *os.File { return nil }
	if r := run(nil, "_serve", "bio"); r.e == nil {
		t.Fatal("_serve without a pipe")
	}
	// No socket directory.
	savedSP := socketPath
	socketPath = func(string) (string, error) { return "", errors.New("no runtime dir") }
	report()
	if r := run(nil, "_serve", "bio"); r.e == nil {
		t.Fatal("socket path error lost")
	}
	socketPath = savedSP
	// Unknown profile: the error reaches the parent on the pipe.
	rd, _ := report()
	if r := run(nil, "_serve", "ghost"); r.e == nil {
		t.Fatal("unknown profile")
	}
	if resp, err := session.DecodeResponse(rd); err != nil || resp.OK || resp.Error == "" {
		t.Fatalf("parent told %+v %v", resp, err)
	}
	// Wrong password from the manager.
	readRef = func(context.Context, string) ([]byte, error) { return []byte("wrong"), nil }
	report()
	if r := run(nil, "_serve", "bio"); r.e == nil {
		t.Fatal("wrong password")
	}
	readRef = func(context.Context, string) ([]byte, error) { return []byte("correct horse"), nil }
	// A container with no filesystem, and a share that cannot start.
	for _, serr := range []error{share.ErrNoFilesystem, errors.New("port busy")} {
		withFakeShare(t, nil, serr)
		report()
		r := run(nil, "_serve", "bio")
		if r.e == nil || (errors.Is(serr, share.ErrNoFilesystem) && !strings.Contains(r.e.Error(), "--fs exfat")) {
			t.Fatalf("%v: %v", serr, r.e)
		}
	}
	// The container is already open elsewhere: refused before any unlock.
	release, err := lockContainer(path)
	if err != nil {
		t.Fatal(err)
	}
	unlocked := false
	readRef = func(context.Context, string) ([]byte, error) { unlocked = true; return nil, errors.New("x") }
	report()
	if r := run(nil, "_serve", "bio"); r.e == nil || !strings.Contains(r.e.Error(), "already open") || unlocked {
		t.Fatalf("lock: %v unlocked=%v", r.e, unlocked)
	}
	release()
	readRef = func(context.Context, string) ([]byte, error) { return []byte("correct horse"), nil }
	// The socket is held by a live session.
	fs := &fakeShare{mount: "/m", done: make(chan struct{})}
	withFakeShare(t, fs, nil)
	sp, _ := socketPath("bio")
	srv, err := session.Listen(sp)
	if err != nil {
		t.Fatal(err)
	}
	report()
	if r := run(nil, "_serve", "bio"); !errors.Is(r.e, session.ErrAlreadyOpen) || !fs.stopped {
		t.Fatalf("socket: %v stopped=%v", r.e, fs.stopped)
	}
	srv.Shutdown()
	// The parent is gone: the ready line cannot be written, the container closes.
	fs = &fakeShare{mount: "/m", done: make(chan struct{})}
	withFakeShare(t, fs, nil)
	rd, _ = report()
	rd.Close()
	if r := run(nil, "_serve", "bio"); r.e == nil || !fs.stopped {
		t.Fatalf("parent gone: %v stopped=%v", r.e, fs.stopped)
	}
	// Detaching fails: the container closes.
	fs = &fakeShare{mount: "/m", done: make(chan struct{})}
	withFakeShare(t, fs, nil)
	detach = func() error { return errors.New("no /dev/null") }
	report()
	if r := run(nil, "_serve", "bio"); r.e == nil || !fs.stopped {
		t.Fatalf("detach: %v stopped=%v", r.e, fs.stopped)
	}
}

// keepAlive holds a *os.File on descriptor 3, which is not ours to close.
var keepAlive *os.File

func TestSessionSeams(t *testing.T) {
	// The defaults the other tests replace.
	// Descriptor 3 of the test binary belongs to someone else: no finalizer may close it.
	f := readyFile()
	if f == nil {
		t.Fatal("no ready file")
	}
	keepAlive = f
	if n := len(stdStreams()); n != 3 {
		t.Fatal(n)
	}
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	boom := errors.New("no cwd")
	savedA, savedP := absPath, osPipe
	t.Cleanup(func() { absPath, osPipe = savedA, savedP })
	absPath = func(string) (string, error) { return "", boom }
	if r := run(nil, "profile", "add", "x", path); !errors.Is(r.e, boom) {
		t.Fatal(r.e)
	}
	osPipe = func() (*os.File, *os.File, error) { return nil, nil, boom }
	if _, err := spawnDaemon(context.Background(), "x", os.Stderr); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = e
}

func TestSecretsOf(t *testing.T) {
	p := profile.New("x", "/x")
	p.PasswordFrom, p.RecoveryFrom, p.PINFrom = "keychain:a/b", "keychain:a/c", "keychain:a/d"
	p.Device, p.Hint, p.Counter, p.TPMDevice = "bio", 2, "tpm", "unix:/s"
	p.TPMAuthFrom, p.TPMEndorsementFrom = "keychain:a/e", "keychain:a/f"
	s := secretsOf(p)
	if s.passwordFrom != p.PasswordFrom || s.recoveryFrom != p.RecoveryFrom || s.pinFrom != p.PINFrom ||
		!s.fido || s.device != "bio" || s.hint != 2 || s.tpm.counter != "tpm" || s.tpm.device != "unix:/s" ||
		s.tpm.authFrom != p.TPMAuthFrom || s.tpm.endorsementAuthFrom != p.TPMEndorsementFrom {
		t.Fatalf("%+v", s)
	}
	if secretsOf(profile.New("y", "/y")).fido {
		t.Fatal("key asked of a profile without one")
	}
}

func TestSpawnDaemon(t *testing.T) {
	saved := executable
	t.Cleanup(func() { executable = saved })
	self, _ := os.Executable()
	executable = func() (string, error) { return self, nil }
	null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer null.Close()

	t.Setenv("THECA_FAKE_DAEMON", "ok")
	i, err := spawnDaemon(context.Background(), "bio", null)
	if err != nil || i.Mount != "/Volumes/THECA" || i.Name != "bio" {
		t.Fatalf("%+v %v", i, err)
	}
	t.Setenv("THECA_FAKE_DAEMON", "err")
	if _, err := spawnDaemon(context.Background(), "bio", null); err == nil || err.Error() != "wrong password" {
		t.Fatal(err)
	}
	t.Setenv("THECA_FAKE_DAEMON", "die")
	if _, err := spawnDaemon(context.Background(), "bio", null); err == nil || !strings.Contains(err.Error(), "without opening") {
		t.Fatal(err)
	}
	t.Setenv("THECA_FAKE_DAEMON", "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := spawnDaemon(ctx, "bio", null); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 20*time.Second {
		t.Fatalf("hang: %v after %v", err, time.Since(start))
	}
	executable = func() (string, error) { return "", errors.New("no exe") }
	if _, err := spawnDaemon(context.Background(), "bio", null); err == nil {
		t.Fatal("executable error lost")
	}
	executable = func() (string, error) { return filepath.Join(t.TempDir(), "nothing"), nil }
	if _, err := spawnDaemon(context.Background(), "bio", null); err == nil {
		t.Fatal("missing binary started")
	}
}

func TestDetachAndLock(t *testing.T) {
	dir := t.TempDir()
	// detachTo points every stream at /dev/null and closes what it held.
	a, _ := os.Create(filepath.Join(dir, "a"))
	b, _ := os.Create(filepath.Join(dir, "b"))
	if err := detachTo(&a, &b); err != nil {
		t.Fatal(err)
	}
	if a.Name() != os.DevNull || b.Name() != os.DevNull {
		t.Fatal(a.Name(), b.Name())
	}
	saved := devNull
	t.Cleanup(func() {
		devNull = saved
		stdStreams = func() []**os.File { return []**os.File{&os.Stdin, &os.Stdout, &os.Stderr} }
	})
	devNull = filepath.Join(dir, "missing", "null")
	if err := detachTo(&a); err == nil {
		t.Fatal("open error lost")
	}
	devNull = saved
	in, out, er := a, b, a
	stdStreams = func() []**os.File { return []**os.File{&in, &out, &er} }
	if err := detachStdio(); err != nil {
		t.Fatal(err)
	}

	f := filepath.Join(dir, "c")
	os.WriteFile(f, nil, 0o600)
	release, err := lockContainer(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockContainer(f); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("second lock: %v", err)
	}
	release()
	release, err = lockContainer(f)
	if err != nil {
		t.Fatal("lock not released:", err)
	}
	release()
	if _, err := lockContainer(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("missing file locked")
	}
	oldF := flock
	t.Cleanup(func() { flock = oldF })
	flock = func(int, int) error { return errors.New("EIO") }
	if _, err := lockContainer(f); err == nil || strings.Contains(err.Error(), "already open") {
		t.Fatalf("other flock error: %v", err)
	}
}

func TestOpenWaitsForTheDaemon(t *testing.T) {
	// `open` bounds the wait, and hands the daemon the terminal's stderr.
	e := newSessionEnv(t)
	_, path, _ := exfatContainer(t)
	e.add(t, "bio", path)
	var dl time.Time
	startDaemon = func(ctx context.Context, _ string, stderr *os.File) (session.Info, error) {
		dl, _ = ctx.Deadline()
		if stderr != os.Stderr {
			t.Error("daemon not given the terminal")
		}
		return session.Info{Mount: "/m"}, nil
	}
	if r := run(nil, "open", "bio"); r.e != nil {
		t.Fatal(r.e)
	}
	if d := time.Until(dl); d <= 0 || d > maxOpenWait {
		t.Fatalf("deadline in %v", d)
	}
}
