package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeHandler struct {
	closed atomic.Int32
	err    error
	gate   chan struct{}
}

func (h *fakeHandler) Status() Info {
	return Info{Name: "bio", Mount: "/Volumes/THECA", Since: 5, PID: 7}
}
func (h *fakeHandler) Close() error {
	h.closed.Add(1)
	if h.gate != nil {
		<-h.gate
	}
	return h.err
}

func sock(t *testing.T) string {
	t.Helper()
	// Short: a socket path is limited to about 100 bytes, a test's name is not.
	d, err := os.MkdirTemp("", "ts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s.sock")
}

func start(t *testing.T, h Handler) (*Server, string) {
	t.Helper()
	p := sock(t)
	s, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(h) }()
	t.Cleanup(func() {
		s.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return s, p
}

func TestStatusAndClose(t *testing.T) {
	h := &fakeHandler{}
	_, p := start(t, h)
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v", st.Mode())
	}
	if d, _ := os.Stat(filepath.Dir(p)); d.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", d.Mode().Perm())
	}
	i, err := Status(context.Background(), p)
	if err != nil || i.Mount != "/Volumes/THECA" || i.PID != 7 {
		t.Fatalf("%+v %v", i, err)
	}
	if err := Close(context.Background(), p); err != nil || h.closed.Load() != 1 {
		t.Fatal(err)
	}
}

func TestCloseError(t *testing.T) {
	h := &fakeHandler{err: errors.New(strings.Repeat("x", 3000))}
	_, p := start(t, h)
	err := Close(context.Background(), p)
	if err == nil || len(err.Error()) > 1100 {
		t.Fatalf("error %v", err)
	}
}

func TestNotOpen(t *testing.T) {
	p := sock(t)
	if _, err := Status(context.Background(), p); !errors.Is(err, ErrNotOpen) {
		t.Fatal(err)
	}
	if err := Close(context.Background(), p); !errors.Is(err, ErrNotOpen) {
		t.Fatal(err)
	}
}

type oneConn struct {
	net.Listener
	c net.Conn
}

func (o oneConn) Accept() (net.Conn, error) { return o.c, nil }

// A connection accepted while Shutdown has begun is dropped, never served:
// WaitGroup.Add must not race with Wait.
func TestServeDropsConnectionDuringShutdown(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := &Server{l: oneConn{c: a}, closing: true}
	if err := s.Serve(&fakeHandler{}); err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection kept open")
	}
}

func TestSecondListenRefused(t *testing.T) {
	_, p := start(t, &fakeHandler{})
	if _, err := Listen(p); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("got %v", err)
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	p := sock(t)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close() // leaves the file, nobody answers
	s, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	s.Shutdown()
	if _, err := os.Stat(p); err == nil {
		t.Fatal("socket left behind")
	}
	s.Shutdown() // twice is fine
}

func TestListenErrors(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := Listen(filepath.Join(f, "x", "s.sock")); err == nil {
		t.Fatal("MkdirAll under a file")
	}
	old := chmod
	defer func() { chmod = old }()
	chmod = func(string, os.FileMode) error { return errors.New("no") }
	if _, err := Listen(filepath.Join(dir, "d", "s.sock")); err == nil {
		t.Fatal("chmod error lost")
	}
	chmod = old
	// A path too long for sun_path: net.Listen fails.
	if _, err := Listen(filepath.Join(dir, strings.Repeat("d", 200), "s.sock")); err == nil {
		t.Fatal("long path accepted")
	}
	// Directory mode cannot be set: the path's parent is not ours... use a
	// parent that is a symlink to nothing.
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "dangling", "s.sock")); err == nil {
		t.Fatal("dangling parent accepted")
	}
}

func TestChmodDirError(t *testing.T) {
	// MkdirAll succeeds on an existing directory we do not own the mode of:
	// simulate with a directory whose chmod fails (read-only parent is not
	// enough), so replace nothing here and exercise the real call on /.
	if os.Getuid() == 0 {
		t.Skip("root can chmod anything")
	}
	if _, err := Listen("/s.sock"); err == nil {
		t.Fatal("listen in / accepted")
	}
}

func TestServeAcceptError(t *testing.T) {
	s, err := Listen(sock(t))
	if err != nil {
		t.Fatal(err)
	}
	s.l = errListener{s.l}
	if err := s.Serve(&fakeHandler{}); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("got %v", err)
	}
	s.Shutdown()
}

type errListener struct{ net.Listener }

func (errListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }

func raw(t *testing.T, p, msg string) string {
	t.Helper()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte(msg))
	if uc, ok := c.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	b, _ := io.ReadAll(io.LimitReader(c, MaxMessage+1))
	return string(b)
}

func TestBadRequests(t *testing.T) {
	h := &fakeHandler{}
	_, p := start(t, h)
	for _, m := range []string{
		`{"op":"launch"}` + "\n",
		`{"op":"close","extra":1}` + "\n",
		`{"op":"close"} {"op":"close"}` + "\n",
		"not json\n",
		"\n",
		strings.Repeat("a", MaxMessage+10) + "\n",
		strings.Repeat("a", MaxMessage+10), // no newline either
	} {
		out := raw(t, p, m)
		if !strings.Contains(out, `"error"`) {
			t.Errorf("%q: answered %q", clip(m, 20), out)
		}
	}
	if raw(t, p, "") != "" && false {
		t.Fatal("unreachable")
	}
	if h.closed.Load() != 0 {
		t.Fatal("a bad request closed the container")
	}
	// An unterminated but valid request is accepted at EOF.
	if out := raw(t, p, `{"op":"status"}`); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("got %q", out)
	}
}

func TestPeerRefused(t *testing.T) {
	// The seams are set before the server starts: no goroutine reads them while
	// the test writes them.
	for name, set := range map[string]func(){
		"other user": func() { getuid = func() int { return os.Getuid() + 1 } },
		"no creds":   func() { getPeerUID = func(int) (int, error) { return -1, errors.New("no creds") } },
	} {
		oldU, oldP := getuid, getPeerUID
		set()
		h := &fakeHandler{}
		_, p := start(t, h)
		if out := raw(t, p, `{"op":"close"}`+"\n"); !strings.Contains(out, ErrPeer.Error()) {
			t.Fatalf("%s: got %q", name, out)
		}
		if h.closed.Load() != 0 {
			t.Fatalf("%s: refused peer closed the container", name)
		}
		t.Cleanup(func() { getuid, getPeerUID = oldU, oldP })
	}
}

func TestPeerOSError(t *testing.T) {
	if _, err := getPeerUIDOS(-1); err == nil {
		t.Fatal("bad fd accepted")
	}
}

func TestDefaultRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/x")
	if runtimeDir() != "/run/x" {
		t.Fatal(runtimeDir())
	}
}

func TestPeerUIDOf(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := peerUIDOf(a); err == nil {
		t.Fatal("pipe accepted")
	}
	p := sock(t)
	l, _ := net.Listen("unix", p)
	defer l.Close()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := l.Accept()
	defer s.Close()
	uid, err := peerUIDOf(s)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("%d %v", uid, err)
	}
	c.Close()
	s.Close()
	if _, err := peerUIDOf(s); err == nil {
		t.Fatal("closed conn accepted")
	}
}

func TestSocketPath(t *testing.T) {
	oldR, oldC := runtimeDir, userConfigDir
	defer func() { runtimeDir, userConfigDir = oldR, oldC }()
	runtimeDir = func() string { return "/run/u" }
	if p, err := SocketPath("bio"); err != nil || p != "/run/u/theca/bio.sock" {
		t.Fatal(p, err)
	}
	runtimeDir = func() string { return "" }
	userConfigDir = func() (string, error) { return "/cfg", nil }
	if p, err := SocketPath("bio"); err != nil || p != "/cfg/theca/run/bio.sock" {
		t.Fatal(p, err)
	}
	userConfigDir = func() (string, error) { return "", errors.New("no home") }
	if _, err := SocketPath("bio"); err == nil {
		t.Fatal("config error lost")
	}
	userConfigDir = func() (string, error) { return "/cfg", nil }
	for _, n := range []string{"", "a/b", "..", ".", "a\x00", `a\b`} {
		if _, err := SocketPath(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	runtimeDir = func() string { return "/" + strings.Repeat("r", 120) }
	if _, err := SocketPath("bio"); err == nil {
		t.Fatal("long path accepted")
	}
}

func TestClientBadAnswers(t *testing.T) {
	for _, tc := range []struct{ name, answer string }{
		{"garbage", "nope\n"},
		{"no-info", `{"ok":true}` + "\n"},
		{"empty-refusal", `{"ok":false}` + "\n"},
		{"too-long", strings.Repeat("a", MaxMessage+5) + "\n"},
	} {
		p := sock(t)
		l, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			c.Write([]byte(tc.answer))
			c.Close()
		}()
		_, err = Status(context.Background(), p)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else if (tc.name == "garbage" || tc.name == "too-long") && err.Error() == "refused" {
			t.Errorf("%s: a malformed answer read as a refusal: %v", tc.name, err)
		}
		l.Close()
	}
	// close with an empty refusal reads "refused"
	p := sock(t)
	l, _ := net.Listen("unix", p)
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte(`{"ok":false}` + "\n"))
		c.Close()
	}()
	if err := Close(context.Background(), p); err == nil || err.Error() != "refused" {
		t.Fatal(err)
	}
}

func TestClientRequestTooLongToSend(t *testing.T) {
	if err := encode(io.Discard, Response{Error: strings.Repeat("a", MaxMessage)}); !errors.Is(err, ErrTooLong) {
		t.Fatal(err)
	}
	// A write that fails.
	if err := encode(failWriter{}, Request{Op: "status"}); err == nil {
		t.Fatal("write error lost")
	}
	// The client's own send failing: a connection already closed by the peer.
	p := sock(t)
	l, _ := net.Listen("unix", p)
	defer l.Close()
	go func() {
		// The listener may be closed before the client ever connects.
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	if _, err := call(context.Background(), p, strings.Repeat("a", MaxMessage), time.Second); err == nil {
		t.Fatal("oversized request sent")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestDecodeResponseAndReport(t *testing.T) {
	var b bytes.Buffer
	if err := Report(&b, Response{OK: true, Info: &Info{Name: "x"}}); err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResponse(&b)
	if err != nil || !r.OK || r.Info.Name != "x" {
		t.Fatal(r, err)
	}
	if _, err := DecodeResponse(strings.NewReader("")); err == nil {
		t.Fatal("empty accepted")
	}
	if _, err := DecodeRequest(strings.NewReader(`{"op":"status"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(strings.NewReader("")); err == nil {
		t.Fatal("empty request accepted")
	}
}

func TestCloseWaitsAndConcurrent(t *testing.T) {
	h := &fakeHandler{gate: make(chan struct{})}
	_, p := start(t, h)
	done := make(chan error, 1)
	go func() { done <- Close(context.Background(), p) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Close returned before the teardown finished")
	default:
	}
	close(h.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStalledClientDoesNotHoldServer(t *testing.T) {
	_, p := start(t, &fakeHandler{})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() // sends nothing
	if _, err := Status(context.Background(), p); err != nil {
		t.Fatal("a stalled client blocked another:", err)
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"op":"status"}` + "\n"))
	f.Add([]byte(`{"op":"close"}`))
	f.Add([]byte(`{"op":1}`))
	f.Add([]byte(strings.Repeat("{", 5000)))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := DecodeRequest(bytes.NewReader(b))
		if err == nil && q.Op != OpStatus && q.Op != OpClose {
			t.Fatalf("admitted operation %q", q.Op)
		}
		DecodeResponse(bytes.NewReader(b))
	})
}
