package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

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
// the share carries decrypted data, and SMB 3.0.2 here is signed, not
// encrypted.
func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--addr %s: only a loopback address is served (decrypted data, no SMB encryption yet)", addr)
	}
	return nil
}

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
)

func serveCmd() *cobra.Command {
	var s secrets
	var addr, share, credOut string
	var every time.Duration
	cmd := &cobra.Command{
		Use:   "serve FILE",
		Short: "Serve the container's filesystem over SMB on a loopback address until interrupted",
		Long: "Unlock the container and serve the exFAT filesystem inside it over SMB on a\n" +
			"loopback address, until Ctrl-C. One account is drawn at random; its URL, user\n" +
			"and password are written to --credentials-out (mode 0600, removed at exit),\n" +
			"never printed or passed as an argument. Writes are committed to the\n" +
			"container every --sync, and when the server stops.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if credOut == "" {
				return errors.New("--credentials-out is required: the share's password is written there")
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
			cr := credentials{
				URL:      fmt.Sprintf("smb://%s/%s", ln.Addr(), share),
				User:     shareUser,
				Password: base64.RawURLEncoding.EncodeToString(pw),
			}
			clear(pw)
			srv := smb.New()
			srv.SetName("THECA")
			srv.AddUser(cr.User, cr.Password)
			err = srv.Share(share, fsys, smb.AllowUsers(cr.User))
			if err == nil {
				err = writeCredentials(credOut, cr)
			}
			if err != nil {
				return closeBoth(c, f, errors.Join(err, ln.Close(), fsys.Close()))
			}
			defer os.Remove(credOut)

			ctx, stop := stopSignals(cmd.Context())
			defer stop()
			done := make(chan error, 1)
			go func() { done <- serveSMB(srv, ln) }()
			fmt.Fprintf(cmd.OutOrStdout(), "serving %s (credentials in %s); Ctrl-C to stop\n", cr.URL, credOut)

			tick := time.NewTicker(every)
			defer tick.Stop()
			var serr error
		loop:
			for {
				select {
				case <-ctx.Done():
					break loop
				case serr = <-done:
					break loop
				case <-tick.C:
					if serr = syncContainer(c); serr != nil {
						break loop
					}
				}
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
	cmd.Flags().StringVar(&credOut, "credentials-out", "", "write the share's URL, user and password here (mode 0600; required)")
	cmd.Flags().DurationVar(&every, "sync", 5*time.Second, "commit writes to the container this often")
	return cmd
}
