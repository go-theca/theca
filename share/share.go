// Package share serves the exFAT filesystem inside an unlocked container over
// SMB on a loopback address, and optionally mounts it in the file manager.
//
// The data is decrypted on its way out, so only a loopback address is served.
// One random account is drawn per share; its password never leaves the
// process except to the OS mount service (and to Password, for a caller that
// must hand it to another client).
//
// The package never closes the container: the caller does, after Stop.
package share

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/go-fileshare/automount"
	exfat "github.com/go-filesystems/exfat"
	"github.com/go-filesystems/smb"

	"github.com/go-theca/theca"
)

// User is the one account a served container has.
const User = "theca"

// unmountTimeout bounds the unmount at Stop: a client that never answers must
// not hold the container open forever.
const unmountTimeout = 30 * time.Second

// ErrNoFilesystem is returned (wrapped) by Start when the container holds no
// exFAT filesystem.
var ErrNoFilesystem = errors.New("the container holds no exFAT filesystem")

// Options configures Start.
type Options struct {
	Addr string        // address to listen on; "127.0.0.1:0" picks a free loopback port
	Name string        // share name (required)
	Sync time.Duration // commit the container this often; must be positive
	// Mount mounts the share in the file manager, with no password dialog. With
	// an unspecified Addr (0.0.0.0, ::) the local mount uses the loopback
	// address on the same port.
	Mount bool
	// Network allows an Addr that is not loopback. It is not a plain switch:
	// the server then REQUIRES message signing and encryption of every session
	// and of the share (go-filesystems/smb RequireSigning, EncryptData and
	// RequireEncryption), so a client that cannot do both is refused. Anyone
	// who can reach the address and has the password can read and write the
	// container's files. False (the default): Addr must be loopback.
	Network bool
}

// Format lays an exFAT filesystem (label THECA) onto the whole logical volume
// of c, through the container itself: nothing decrypted is written anywhere
// else. It erases what the volume held. A volume too small for exFAT is
// refused. This is what `theca create --fs exfat` does, so a container made
// by any front end can be served by Start.
func Format(c *theca.Container) error {
	fsys, err := exfat.FormatImage(c, c.Size(), exfat.FormatConfig{Label: "THECA"})
	if err != nil {
		return err
	}
	return fsys.Close()
}

// CheckAddr refuses a malformed address, and unless network is set one that is
// not on the loopback interface: the share carries decrypted data, and beyond
// loopback it is served only with signing and encryption required (Network).
func CheckAddr(addr string, network bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); !network && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("address %s: only a loopback address is served (the data is decrypted); Network (--network) serves another one, with signing and encryption required", addr)
	}
	return nil
}

// localHost is the host:port a client on this machine reaches a listener at:
// the listener's own address, except that an unspecified IP (0.0.0.0, ::) is
// not somewhere a client can connect, so it becomes 127.0.0.1 on the same
// port. (Go binds both of them dual-stack, so 127.0.0.1 reaches either.)
func localHost(a net.Addr) string {
	t, ok := a.(*net.TCPAddr)
	if !ok || !t.IP.IsUnspecified() {
		return a.String()
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(t.Port))
}

// mounted is what a mount hands back: automount.Mounted, or a test's fake.
type mounted interface {
	Path() string
	Unmount(ctx context.Context) error
}

// Seams the tests replace.
var (
	syncContainer = func(c *theca.Container) error { return c.Sync() }
	serveSMB      = func(srv *smb.Server, ln net.Listener) error { return srv.Serve(ln) }
	// mountShare mounts the share in the file manager, with no dialog: the
	// password goes to the OS mount service as a value (go-fileshare/automount).
	mountShare = func(ctx context.Context, u *url.URL, user, password string) (mounted, error) {
		return asMounted(automount.Mount(ctx, automount.Share{URL: u, User: user, Password: password}, automount.Options{}))
	}
)

// asMounted keeps a nil *automount.Mounted from becoming a non-nil interface.
func asMounted(m *automount.Mounted, err error) (mounted, error) {
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Share is a running share. Create one with Start; end it with Stop.
type Share struct {
	url      string
	addr     string
	password string
	mnt      mounted
	srv      *smb.Server
	fsys     interface{ Close() error }

	stopCh   chan struct{}
	done     chan struct{}
	loopErr  error // written before done closes
	stopOnce sync.Once
	stopErr  error
}

// Start opens the exFAT filesystem inside c through the container itself,
// listens on o.Addr, serves it, and (with o.Mount) mounts it. The container
// is committed every o.Sync. ctx bounds the mount and, when it ends, ends the
// share (Done closes, Err is nil); Stop must still be called.
//
// A container with no exFAT inside is refused with ErrNoFilesystem. On any
// error nothing is left running, and c is untouched.
func Start(ctx context.Context, c *theca.Container, o Options) (*Share, error) {
	if err := CheckAddr(o.Addr, o.Network); err != nil {
		return nil, err
	}
	if o.Sync <= 0 {
		return nil, errors.New("sync must be positive")
	}
	fsys, err := exfat.OpenReader(c, c.Size())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoFilesystem, err)
	}
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, errors.Join(err, fsys.Close())
	}
	pw := make([]byte, 24)
	rand.Read(pw)
	password := base64.RawURLEncoding.EncodeToString(pw)
	clear(pw)
	u := &url.URL{Scheme: "smb", Host: localHost(ln.Addr()), Path: "/" + o.Name}
	srv := smb.New()
	srv.SetName("THECA")
	srv.AddUser(User, password)
	shareOpts := []smb.ShareOption{smb.AllowUsers(User)}
	if o.Network {
		// Beyond loopback, both or nothing: a session that does not sign and
		// encrypt is refused, and so is a share reached without encryption.
		srv.RequireSigning = true
		srv.EncryptData = true
		shareOpts = append(shareOpts, smb.RequireEncryption())
	}
	if err := srv.Share(o.Name, fsys, shareOpts...); err != nil {
		return nil, errors.Join(err, ln.Close(), fsys.Close())
	}
	s := &Share{
		url: u.String(), addr: ln.Addr().String(), password: password, srv: srv, fsys: fsys,
		stopCh: make(chan struct{}), done: make(chan struct{}),
	}
	served := make(chan error, 1)
	go func() { served <- serveSMB(srv, ln) }()
	if o.Mount {
		m, err := mountShare(ctx, u, User, password)
		if err != nil {
			srv.Close()
			return nil, errors.Join(fmt.Errorf("mounting %s: %w", s.url, err), fsys.Close())
		}
		s.mnt = m
	}
	go s.loop(ctx, c, served, o.Sync)
	return s, nil
}

// loop commits the container every tick until the context ends or Stop is
// called (no error), or the server or a commit fails (that error).
func (s *Share) loop(ctx context.Context, c *theca.Container, served <-chan error, every time.Duration) {
	defer close(s.done)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case err := <-served:
			s.loopErr = err
			return
		case <-tick.C:
			if err := syncContainer(c); err != nil {
				s.loopErr = err
				return
			}
		}
	}
}

// URL is the share's address as a client on this machine reaches it, for
// example smb://127.0.0.1:58738/theca. When listening on an unspecified
// address (0.0.0.0, ::) it names the loopback address on the same port; a
// client elsewhere uses this machine's address with that port.
func (s *Share) URL() string { return s.url }

// Addr is the address the share listens on, as bound, for example
// 0.0.0.0:4455.
func (s *Share) Addr() string { return s.addr }

// User is the account name of the share.
func (s *Share) User() string { return User }

// Password is the share's password. It is a secret: it exists for a caller
// that hands the account to another client (theca serve --credentials-out).
// Never show it, log it or put it in an argument.
func (s *Share) Password() string { return s.password }

// MountPath is where the share is mounted, or "" when it is not.
func (s *Share) MountPath() string {
	if s.mnt == nil {
		return ""
	}
	return s.mnt.Path()
}

// Done is closed when the share ends by itself: its context ended, the server
// failed or a commit failed. Stop closes it too.
func (s *Share) Done() <-chan struct{} { return s.done }

// Err is the error that ended the share, nil while it runs or when it ended
// without one. Read it after Done is closed.
func (s *Share) Err() error {
	select {
	case <-s.done:
		return s.loopErr
	default:
		return nil
	}
}

// Stop unmounts (own 30 s context, so a cancelled ctx does not cut it short),
// closes the server, then closes the filesystem, which commits. It never
// closes the container. It returns the error that ended the share, if any,
// joined with the stop errors; calling it again returns the same result.
func (s *Share) Stop() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		<-s.done
		err := s.loopErr
		// Unmount first, while the server still answers: the client flushes
		// what it holds through it.
		if s.mnt != nil {
			uctx, cancel := context.WithTimeout(context.Background(), unmountTimeout)
			if uerr := s.mnt.Unmount(uctx); uerr != nil {
				err = errors.Join(err, fmt.Errorf("unmounting %s: %w", s.mnt.Path(), uerr))
			}
			cancel()
		}
		// Closing the server only stops the listener: its own error says
		// nothing about the data, which the filesystem close commits.
		s.srv.Close()
		s.stopErr = errors.Join(err, s.fsys.Close())
	})
	return s.stopErr
}
