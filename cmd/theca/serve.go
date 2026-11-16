package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/share"
)

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
	return share.Format(c)
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

// sharer is what serve needs of a running share: *share.Share, or a test's fake.
type sharer interface {
	URL() string
	Addr() string
	User() string
	Password() string
	MountPath() string
	Done() <-chan struct{}
	Stop() error
}

// Seams the tests replace.
var (
	stopSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	// startShare keeps a nil *share.Share from becoming a non-nil interface.
	startShare = func(ctx context.Context, c *theca.Container, o share.Options) (sharer, error) {
		sh, err := share.Start(ctx, c, o)
		if err != nil {
			return nil, err
		}
		return sh, nil
	}
)

func serveCmd() *cobra.Command {
	var s secrets
	var addr, name, credOut string
	var every time.Duration
	var doMount, network bool
	cmd := &cobra.Command{
		Use:   "serve FILE",
		Short: "Serve the container's filesystem over SMB on a loopback address (or, with --network, any) until interrupted",
		Long: "Unlock the container and serve the exFAT filesystem inside it over SMB on a\n" +
			"loopback address (--network: any address, with signing AND encryption\n" +
			"required of every client), until Ctrl-C. One account is drawn at random, never printed\n" +
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
			if err := share.CheckAddr(addr, network); err != nil {
				return err
			}
			if every <= 0 {
				return errors.New("--sync must be positive")
			}
			c, f, err := open(cmd, args[0], &s, true)
			if err != nil {
				return err
			}
			ctx, stop := stopSignals(cmd.Context())
			defer stop()
			sh, err := startShare(ctx, c, share.Options{Addr: addr, Name: name, Sync: every, Mount: doMount, Network: network})
			if err != nil {
				if errors.Is(err, share.ErrNoFilesystem) {
					err = fmt.Errorf("%w (create one with --fs exfat)", err)
				}
				return closeBoth(c, f, err)
			}
			if credOut != "" {
				cr := credentials{URL: sh.URL(), User: sh.User(), Password: sh.Password()}
				if err := writeCredentials(credOut, cr); err != nil {
					return closeBoth(c, f, errors.Join(err, sh.Stop()))
				}
				defer os.Remove(credOut)
			}
			if network {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: --network: listening on %s; anyone on the network who can reach it and has the password can read and write the container's files (every client must sign and encrypt); the password is in --credentials-out\n", sh.Addr())
			}
			out := cmd.OutOrStdout()
			if credOut != "" {
				fmt.Fprintf(out, "serving %s (credentials in %s); Ctrl-C to stop\n", sh.URL(), credOut)
			} else {
				fmt.Fprintf(out, "serving %s; Ctrl-C to stop\n", sh.URL())
			}
			if p := sh.MountPath(); p != "" {
				fmt.Fprintf(out, "mounted at %s\n", p)
			}
			<-sh.Done()
			return closeBoth(c, f, sh.Stop())
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0", "loopback address to listen on (port 0: a free one)")
	cmd.Flags().StringVar(&name, "share", "theca", "share name")
	cmd.Flags().StringVar(&credOut, "credentials-out", "", "write the share's URL, user and password here (mode 0600, removed at exit)")
	cmd.Flags().BoolVar(&network, "network", false, "allow a --addr that is not loopback: signing and encryption are then REQUIRED of every client")
	cmd.Flags().BoolVar(&doMount, "mount", false, "mount the share in the file manager (no password dialog) and unmount it at stop")
	cmd.Flags().DurationVar(&every, "sync", 5*time.Second, "commit writes to the container this often")
	return cmd
}
