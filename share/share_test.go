package share

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-fileshare/automount"
	exfat "github.com/go-filesystems/exfat"
	"github.com/go-filesystems/smb"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/kdf"
)

func TestMain(m *testing.M) {
	// Small Argon2id profiles: the production table is 2 GiB and up.
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	os.Exit(m.Run())
}

// newContainer creates a 4 MiB container, formatted with exFAT or left raw.
// The container is closed at the end of the test, never by the share.
func newContainer(t *testing.T, withFS bool) *theca.Container {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "c.theca"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4 << 20); err != nil {
		t.Fatal(err)
	}
	c, _, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
		Sectors: (4 << 20) / theca.SectorSize, Password: []byte("correct horse"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); f.Close() })
	if withFS {
		if err := Format(c); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestFormat(t *testing.T) {
	c := newContainer(t, true)
	fsys, err := exfat.OpenReader(c, c.Size())
	if err != nil {
		t.Fatalf("no exFAT after Format: %v", err)
	}
	fsys.Close()
	// Too small for exFAT: refused.
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "s.theca"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Truncate(1 << 20)
	small, _, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{Sectors: 1, Password: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	if err := Format(small); err == nil {
		t.Fatal("a one-sector volume was formatted")
	}
}

func opts() Options {
	return Options{Addr: "127.0.0.1:0", Name: "theca", Sync: 10 * time.Millisecond}
}

func TestStartStop(t *testing.T) {
	c := newContainer(t, true)
	s, err := Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.URL(), "smb://127.0.0.1:") || !strings.HasSuffix(s.URL(), "/theca") {
		t.Fatalf("URL %q", s.URL())
	}
	if !userRE.MatchString(s.User()) || len(s.Password()) < 30 || s.MountPath() != "" {
		t.Fatalf("user %q, password %d chars, mount %q", s.User(), len(s.Password()), s.MountPath())
	}
	if s.Err() != nil {
		t.Fatalf("Err while running: %v", s.Err())
	}
	host := strings.TrimSuffix(strings.TrimPrefix(s.URL(), "smb://"), "/theca")
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond) // let a few syncs run
	select {
	case <-s.Done():
		t.Fatal("Done closed while running")
	default:
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil { // idempotent
		t.Fatal(err)
	}
	<-s.Done()
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	// The port is closed, and the container is still open and usable.
	if conn, err := net.DialTimeout("tcp", host, time.Second); err == nil {
		conn.Close()
		t.Fatal("still listening after Stop")
	}
	if err := c.Sync(); err != nil {
		t.Fatalf("container after Stop: %v", err)
	}
	fsys, err := exfat.OpenReader(c, c.Size())
	if err != nil {
		t.Fatalf("filesystem after Stop: %v", err)
	}
	fsys.Close()
}

func TestStartRefusals(t *testing.T) {
	good := newContainer(t, true)
	raw := newContainer(t, false)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	with := func(f func(*Options)) Options { o := opts(); f(&o); return o }
	for name, tc := range map[string]struct {
		c *theca.Container
		o Options
	}{
		"network address": {good, with(func(o *Options) { o.Addr = "0.0.0.0:0" })},
		"hostname":        {good, with(func(o *Options) { o.Addr = "example.org:0" })},
		"bad address":     {good, with(func(o *Options) { o.Addr = "nope" })},
		"zero sync":       {good, with(func(o *Options) { o.Sync = 0 })},
		"port in use":     {good, with(func(o *Options) { o.Addr = busy.Addr().String() })},
		"empty name":      {good, with(func(o *Options) { o.Name = "" })},
		"raw volume":      {raw, opts()},
	} {
		s, err := Start(context.Background(), tc.c, tc.o)
		if err == nil {
			s.Stop()
			t.Errorf("%s: accepted", name)
		}
		if name == "raw volume" && !errors.Is(err, ErrNoFilesystem) {
			t.Errorf("raw volume: %v", err)
		}
	}
	// Refusals left the good container usable: it still serves.
	s, err := Start(context.Background(), good, opts())
	if err != nil {
		t.Fatalf("after refusals: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	// localhost is a loopback name.
	if err := CheckAddr("localhost:0", false); err != nil {
		t.Fatal(err)
	}
	// Without Network a refusal names it; with it any well-formed address passes.
	if err := CheckAddr("0.0.0.0:4455", false); err == nil || !strings.Contains(err.Error(), "--network") {
		t.Fatalf("0.0.0.0 without Network: %v", err)
	}
	for _, addr := range []string{"0.0.0.0:4455", "[::]:4455", "192.0.2.7:4455", "example.org:4455"} {
		if err := CheckAddr(addr, true); err != nil {
			t.Errorf("%s with Network: %v", addr, err)
		}
	}
	if err := CheckAddr("nope", true); err == nil {
		t.Error("a malformed address passed with Network")
	}
}

func TestLocalHost(t *testing.T) {
	for _, c := range []struct {
		in   net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv4zero, Port: 4455}, "127.0.0.1:4455"},
		{&net.TCPAddr{IP: net.IPv6unspecified, Port: 4455}, "127.0.0.1:4455"},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4455}, "192.0.2.7:4455"},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4455}, "127.0.0.1:4455"},
		{&net.UnixAddr{Name: "sock", Net: "unix"}, "sock"},
	} {
		if got := localHost(c.in); got != c.want {
			t.Errorf("localHost(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// dial opens an SMB session to the share as a client that is not ours.
func dial(t *testing.T, s *Share, dialect uint16, signing bool) (*smb2.Share, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{SpecifiedDialect: dialect, RequireMessageSigning: signing},
		Initiator:  &smb2.NTLMInitiator{User: s.User(), Password: s.Password()},
	}
	sess, err := d.Dial(ctx, strings.TrimSuffix(strings.TrimPrefix(s.URL(), "smb://"), "/theca"))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { sess.Logoff() })
	return sess.Mount("theca")
}

// Beyond loopback the server requires signing AND encryption: a client that
// can do both is served, one that cannot encrypt (SMB 2.1) is refused.
func TestNetworkRequiresSigningAndEncryption(t *testing.T) {
	c := newContainer(t, true)
	o := opts()
	o.Addr, o.Network = "0.0.0.0:0", true
	s, err := Start(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if _, port, _ := net.SplitHostPort(s.Addr()); port == "" || !strings.HasPrefix(s.URL(), "smb://127.0.0.1:") {
		t.Fatalf("Addr %q, URL %q", s.Addr(), s.URL())
	}
	// 3.1.1, the client does not ask for signing: the server insists.
	fs, err := dial(t, s, 0x0311, false)
	if err != nil {
		t.Fatalf("a signing, encrypting client was refused: %v", err)
	}
	if err := fs.WriteFile("hello.txt", []byte("over the network"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := fs.ReadFile("hello.txt"); err != nil || string(b) != "over the network" {
		t.Fatalf("read back %q: %v", b, err)
	}
	fs.Umount()
	// 2.1 cannot encrypt: refused at the session or at the tree connect.
	if fs, err := dial(t, s, 0x0210, false); err == nil {
		fs.Umount()
		t.Fatal("a client that cannot encrypt reached the share")
	}
}

// Without Network on loopback nothing is imposed: a 2.1 client is served.
func TestLoopbackImposesNothingExtra(t *testing.T) {
	c := newContainer(t, true)
	s, err := Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	fs, err := dial(t, s, 0x0210, false)
	if err != nil {
		t.Fatalf("a plain loopback client was refused: %v", err)
	}
	fs.Umount()
}

func TestShareEndsOnAFailure(t *testing.T) {
	c := newContainer(t, true)
	boom := errors.New("boom")

	// The commit failing ends the share and reports it.
	saved := syncContainer
	t.Cleanup(func() { syncContainer = saved })
	syncContainer = func(*theca.Container) error { return boom }
	s, err := Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	<-s.Done()
	if !errors.Is(s.Err(), boom) || !errors.Is(s.Stop(), boom) {
		t.Fatalf("sync failure: Err %v", s.Err())
	}
	syncContainer = saved

	// The server failing ends it too.
	savedServe := serveSMB
	t.Cleanup(func() { serveSMB = savedServe })
	serveSMB = func(*smb.Server, net.Listener) error { return boom }
	s, err = Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	<-s.Done()
	if !errors.Is(s.Err(), boom) || !errors.Is(s.Stop(), boom) {
		t.Fatalf("server failure: Err %v", s.Err())
	}
	serveSMB = savedServe

	// The context ending ends it, with no error.
	ctx, cancel := context.WithCancel(context.Background())
	s, err = Start(ctx, c, opts())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-s.Done()
	if s.Err() != nil || s.Stop() != nil {
		t.Fatalf("context end: %v", s.Err())
	}
}

// fakeMount records what Start asked of the OS mount.
type fakeMount struct {
	url, user string
	pwLen     int
	unmounted bool
	unmountTo error
}

func (m *fakeMount) Path() string { return "/Volumes/theca" }
func (m *fakeMount) Unmount(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err() // a stopped context must not reach the unmount
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("unmount has no deadline")
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
		if mountErr != nil {
			return nil, mountErr
		}
		return fm, nil
	}
}

func TestMount(t *testing.T) {
	c := newContainer(t, true)
	fm := &fakeMount{}
	withFakeMount(t, fm, nil)
	o := opts()
	o.Mount = true
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, c, o)
	if err != nil {
		t.Fatal(err)
	}
	if s.MountPath() != "/Volumes/theca" {
		t.Fatalf("MountPath %q", s.MountPath())
	}
	time.Sleep(30 * time.Millisecond)
	cancel() // the stop context is cancelled, the unmount must still run
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fm.url, "smb://127.0.0.1:") || !strings.HasSuffix(fm.url, "/theca") || fm.user != s.User() || !userRE.MatchString(fm.user) || fm.pwLen < 30 {
		t.Fatalf("mounted %q as %q (password %d chars)", fm.url, fm.user, fm.pwLen)
	}
	if !fm.unmounted {
		t.Fatal("not unmounted at Stop")
	}
}

func TestMountFailures(t *testing.T) {
	c := newContainer(t, true)
	boom := errors.New("boom")
	o := opts()
	o.Mount = true

	// A mount that fails leaves nothing running and says so.
	withFakeMount(t, &fakeMount{}, boom)
	s, err := Start(context.Background(), c, o)
	if s != nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "mounting smb://127.0.0.1:") {
		t.Fatalf("mount failure: %v %v", s, err)
	}

	// An unmount that fails is reported, and the filesystem is still closed.
	withFakeMount(t, &fakeMount{unmountTo: boom}, nil)
	s, err = Start(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); !errors.Is(err, boom) || !strings.Contains(err.Error(), "unmounting /Volumes/theca") {
		t.Fatalf("unmount failure: %v", err)
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

// userRE is what an account name looks like: the prefix and 8 base32 characters.
var userRE = regexp.MustCompile(`^theca-[a-z2-7]{8}$`)

// Every share has its own account name: macOS replays a stale credential for a
// fixed name on 127.0.0.1 and fails the second mount with errno 80.
func TestEveryShareHasItsOwnAccountName(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		u := newUser()
		if !userRE.MatchString(u) || seen[u] {
			t.Fatalf("name %q (a repeat: %v)", u, seen[u])
		}
		seen[u] = true
	}
	// And a running share serves exactly its own name, not the prefix alone.
	c := newContainer(t, true)
	s1, err := Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	u1 := s1.User()
	s1.Stop()
	s2, err := Start(context.Background(), c, opts())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Stop()
	if u1 == s2.User() {
		t.Fatalf("two shares both named %q", u1)
	}
	if _, err := dial(t, s2, 0x0311, false); err != nil {
		t.Fatalf("its own name does not log in: %v", err)
	}
	other := &Share{user: u1, password: s2.Password(), url: s2.URL()}
	if _, err := dial(t, other, 0x0311, false); err == nil {
		t.Fatal("another share's account name logged in")
	}
}

// TestLiveRepeatedNetworkMounts mounts a REAL network share ten times in one
// process: start, mount, unmount, stop. A fixed account name made the second
// one fail on macOS. It mounts volumes on this machine, so it runs only when
// asked:
//
//	THECA_SHARE_LIVE=1 go test -count=1 -run TestLiveRepeatedNetworkMounts -v ./share
func TestLiveRepeatedNetworkMounts(t *testing.T) {
	if os.Getenv("THECA_SHARE_LIVE") == "" {
		t.Skip("set THECA_SHARE_LIVE=1 to mount real shares")
	}
	c := newContainer(t, true)
	o := opts()
	o.Addr, o.Network, o.Mount = "0.0.0.0:0", true, true
	for i := 0; i < 10; i++ {
		s, err := Start(context.Background(), c, o)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		t.Logf("round %d: %s mounted at %s", i, s.User(), s.MountPath())
		if s.MountPath() == "" {
			t.Fatalf("round %d: not mounted", i)
		}
		if err := s.Stop(); err != nil {
			t.Fatalf("round %d: stop: %v", i, err)
		}
	}
}
