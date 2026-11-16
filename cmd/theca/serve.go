package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-fileshare/automount"
	exfat "github.com/go-filesystems/exfat"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/smb"
	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
)

// shareUser is the one account a served container has.
const shareUser = "theca"

// credentials is what serve writes for whoever mounts the share: the
// GUI's automount, or a person reading the file.
type credentials struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// formatFS lays an exFAT filesystem onto a freshly created container when
// asked to (create has already refused any other --fs value).
func formatFS(c *theca.Container, kind string) error {
	if kind != "exfat" {
		return nil
	}
	fsys, err := exfat.FormatImage(c, c.Size(), exfat.FormatConfig{Label: "THECA"})
	if err != nil {
		return err
	}
	return fsys.Close()
}

// openFS opens the filesystem inside an unlocked container, through the
// container itself: nothing decrypted is written anywhere else.
func openFS(c *theca.Container) (filesystem.Filesystem, error) {
	fsys, err := exfat.OpenReader(c, c.Size())
	if err != nil {
		return nil, fmt.Errorf("the container holds no exFAT filesystem (create one with --fs exfat): %w", err)
	}
	return fsys, nil
}

// loopbackOnly refuses an address that is not on the loopback interface:
// the share carries decrypted data, and the SMB server still accepts a
// replayed frame (go-filesystems/smb#53) and an unsigned request on a session
// that requires signing (go-filesystems/smb#54).
func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--addr %s: only a loopback address is served (the data is decrypted)", addr)
	}
	return nil
}

// mounted is what a mount hands back: automount.Mounted, or a test's fake.
type mounted interface {
	Path() string
	Unmount(ctx context.Context) error
}

// unmountTimeout bounds the unmount at stop: the context that stopped serve
// is already cancelled, and a client that never answers must not hold the
// container open forever.
const unmountTimeout = 30 * time.Second

// writeCredentials creates path with mode 0600, refusing an existing file.
func writeCredentials(path string, cr credentials) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(cr) // three strings: cannot fail
	_, werr := f.Write(append(data, '\n'))
	return errors.Join(werr, f.Close())
}

// Seams the tests replace.
var (
	stopSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
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

// serveLoop commits the container every tick until the context ends (nil)
// or the server or a commit fails (that error).
func serveLoop(ctx context.Context, c *theca.Container, done <-chan error, every time.Duration) error {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return err
		case <-tick.C:
			if err := syncContainer(c); err != nil {
				return err
			}
		}
	}
}

func serveCmd() *cobra.Command {
	var s secrets
	var addr, share, credOut string
	var every time.Duration
	var doMount bool
	cmd := &cobra.Command{
		Use:   "serve FILE",
		Short: "Serve the container's filesystem over SMB on a loopback address until interrupted",
		Long: "Unlock the container and serve the exFAT filesystem inside it over SMB on a\n" +
			"loopback address, until Ctrl-C. One account is drawn at random, never printed\n" +
			"or passed as an argument. --mount mounts the share in the file manager\n" +
			"(Finder, GNOME Files, Explorer) with no password dialog, and unmounts it at\n" +
			"stop; --credentials-out writes the URL, user and password to a file (mode\n" +
			"0600, removed at exit) for another client. Writes are committed to the\n" +
			"container every --sync, and when the server stops.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if credOut == "" && !doMount {
				return errors.New("nothing could reach the share: give --mount, or --credentials-out to write its password to a file")
			}
			if err := loopbackOnly(addr); err != nil {
				return err
			}
			if every <= 0 {
				return errors.New("--sync must be positive")
			}
			c, f, err := open(cmd, args[0], &s, true)
			if err != nil {
				return err
			}
			fsys, err := openFS(c)
			if err != nil {
				return closeBoth(c, f, err)
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return closeBoth(c, f, errors.Join(err, fsys.Close()))
			}
			pw := make([]byte, 24)
			rand.Read(pw)
			u := &url.URL{Scheme: "smb", Host: ln.Addr().String(), Path: "/" + share}
			cr := credentials{
				URL:      u.String(),
				User:     shareUser,
				Password: base64.RawURLEncoding.EncodeToString(pw),
			}
			clear(pw)
			srv := smb.New()
			srv.SetName("THECA")
			srv.AddUser(cr.User, cr.Password)
			err = srv.Share(share, fsys, smb.AllowUsers(cr.User))
			if err == nil && credOut != "" {
				err = writeCredentials(credOut, cr)
			}
			if err != nil {
				return closeBoth(c, f, errors.Join(err, ln.Close(), fsys.Close()))
			}
			if credOut != "" {
				defer os.Remove(credOut)
			}

			ctx, stop := stopSignals(cmd.Context())
			defer stop()
			done := make(chan error, 1)
			go func() { done <- serveSMB(srv, ln) }()
			out := cmd.OutOrStdout()
			if credOut != "" {
				fmt.Fprintf(out, "serving %s (credentials in %s); Ctrl-C to stop\n", cr.URL, credOut)
			} else {
				fmt.Fprintf(out, "serving %s; Ctrl-C to stop\n", cr.URL)
			}

			var serr error
			var mnt mounted
			if doMount {
				if mnt, serr = mountShare(ctx, u, cr.User, cr.Password); serr != nil {
					serr = fmt.Errorf("mounting %s: %w", cr.URL, serr)
				} else {
					fmt.Fprintf(out, "mounted at %s\n", mnt.Path())
				}
			}
			if serr == nil {
				serr = serveLoop(ctx, c, done, every)
			}
			// Unmount first, while the server still answers: the client
			// flushes what it holds through it.
			if mnt != nil {
				uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unmountTimeout)
				if uerr := mnt.Unmount(uctx); uerr != nil {
					serr = errors.Join(serr, fmt.Errorf("unmounting %s: %w", mnt.Path(), uerr))
				}
				cancel()
			}
			// Closing the server only stops the listener: its own error says
			// nothing about the data, which the filesystem and the container
			// closes below commit.
			srv.Close()
			return closeBoth(c, f, errors.Join(serr, fsys.Close()))
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0", "loopback address to listen on (port 0: a free one)")
	cmd.Flags().StringVar(&share, "share", "theca", "share name")
	cmd.Flags().StringVar(&credOut, "credentials-out", "", "write the share's URL, user and password here (mode 0600, removed at exit)")
	cmd.Flags().BoolVar(&doMount, "mount", false, "mount the share in the file manager (no password dialog) and unmount it at stop")
	cmd.Flags().DurationVar(&every, "sync", 5*time.Second, "commit writes to the container this often")
	return cmd
}
