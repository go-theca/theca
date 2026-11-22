package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/lockwatch"
	"github.com/go-theca/theca/internal/memlock"
	"github.com/go-theca/theca/profile"
	"github.com/go-theca/theca/session"
	"github.com/go-theca/theca/share"
)

// Seams the tests replace.
var (
	// profileStore is the profile file of this user.
	profileStore = func() (profile.Store, error) {
		p, err := profile.DefaultPath()
		return profile.Store{Path: p}, err
	}
	socketPath = session.SocketPath
	watchLock  = lockwatch.Watch
	// startDaemon runs `theca _serve NAME` detached and waits until the container
	// is open and mounted (or the attempt failed).
	startDaemon = spawnDaemon
	// readyFile is the pipe the daemon tells its parent through.
	readyFile  = session.ReadyFile
	detach     = detachStdio
	lockFile   = lockContainer
	executable = os.Executable
	absPath    = filepath.Abs
)

const refHelp = "keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT, keepassxc:URL or systemd-creds:NAME (checked, never read; file: is refused)"

// maxOpenWait bounds how long `theca open` waits for the unlock (a person has to
// touch a key, and may need a minute).
const maxOpenWait = 5 * time.Minute

// ---- profile ----

func profileCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "profile",
		Short: "Name a container once: its secret-manager entries, its key, its counter (references only, never a secret)",
		Long: "A profile names a container and how it opens, in containers.toml (mode 0600,\n" +
			"in the user's configuration directory). It holds only references: the\n" +
			"container's path, the secret-manager entry of the password (keychain:,\n" +
			"secretservice: or keepassxc:), the key's ID or name, the counter. Never a\n" +
			"password, a PIN or a recovery code. `theca open NAME` then asks the manager and\n" +
			"the key, and nothing else.",
	}
	root.AddCommand(profileAddCmd(), profileListCmd(), profileRemoveCmd())
	return root
}

func profileAddCmd() *cobra.Command {
	var p profile.Profile
	var replace bool
	cmd := &cobra.Command{
		Use:   "add NAME FILE",
		Short: "Add a profile; the references are checked for syntax, never read",
		Example: "  theca profile add bio ~/vault/bio.theca \\\n" +
			"      --password-from 'keepassxc:https://theca.invalid/bio' --device bio",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := absPath(args[1])
			if err != nil {
				return err
			}
			p.Name, p.File = args[0], abs
			if err := p.Validate(); err != nil {
				return err
			}
			if st, err := os.Stat(p.File); err != nil {
				return err
			} else if !st.Mode().IsRegular() {
				return fmt.Errorf("%s: not a regular file", p.File)
			}
			st, err := profileStore()
			if err != nil {
				return err
			}
			if err := st.Add(p, replace); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "profile %s added (%s); open it with: theca open %s\n", p.Name, st.Path, p.Name)
			return nil
		},
	}
	p = profile.New("", "")
	f := cmd.Flags()
	f.StringVar(&p.PasswordFrom, "password-from", "", "the password, a reference: "+refHelp)
	f.StringVar(&p.RecoveryFrom, "recovery-from", "", "the recovery code, same references")
	f.StringVar(&p.PINFrom, "pin-from", "", "the security key's PIN, same references; unused by a key with a fingerprint")
	f.StringVar(&p.Device, "device", "", "the security key's `ID` or name (fido list prints them); implies --fido2")
	f.BoolVar(&p.FIDO2, "fido2", false, "use the attached security key (without naming it)")
	f.IntVar(&p.Hint, "hint", 0, "Argon2id profile the password was created with: 0, 1 or 2")
	f.StringVar(&p.Counter, "counter", "", "rollback counter: tpm or empty")
	f.StringVar(&p.TPMDevice, "tpm-device", "", "TPM device: a path, or unix:SOCKET")
	f.StringVar(&p.TPMAuthFrom, "tpm-auth-from", "", "the counter's authValue, only for a counter made with an explicit one (a derived authValue needs nothing): "+refHelp)
	f.StringVar(&p.TPMEndorsementFrom, "tpm-endorsement-auth-from", "", "the TPM's endorsement password, if it has one: "+refHelp)
	f.StringVar(&p.Share, "share", profile.DefaultShare, "share name")
	f.DurationVar(&p.Sync, "sync", profile.DefaultSync, "commit writes to the container this often")
	f.BoolVar(&p.CloseOnLock, "close-on-lock", true, "close the container when the screen locks, the machine sleeps or the session ends")
	f.BoolVar(&replace, "replace", false, "overwrite a profile of the same name")
	return cmd
}

func profileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := profileStore()
			if err != nil {
				return err
			}
			ps, err := st.List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tFILE\tPASSWORD\tKEY\tCLOSE-ON-LOCK")
			for _, p := range ps {
				key := "-"
				if p.UsesKey() {
					key = "yes"
					if p.Device != "" {
						key = p.Device
					}
				}
				pw := p.PasswordFrom
				if pw == "" {
					pw = "(terminal)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\n", p.Name, p.File, pw, key, p.CloseOnLock)
			}
			return w.Flush()
		},
	}
}

func profileRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove a profile (the container and the secret-manager entries stay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := profileStore()
			if err != nil {
				return err
			}
			if err := st.Remove(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "profile %s removed\n", args[0])
			return nil
		},
	}
}

// ---- open, close, status ----

func openCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "open NAME",
		Short: "Unlock a profile's container, mount it in the file manager, and leave it running in the background",
		Long: "Unlock the container the profile NAME names (the password from its secret\n" +
			"manager, one touch of the key), serve it over SMB on a loopback address and\n" +
			"mount it in the file manager, then free the terminal: a background process\n" +
			"keeps the container open. `theca close NAME` unmounts, commits and closes it;\n" +
			"so do a screen lock, a sleep and a logout (profile option close-on-lock).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			st, err := profileStore()
			if err != nil {
				return err
			}
			if _, err := st.Get(name); err != nil {
				return err
			}
			sp, err := socketPath(name)
			if err != nil {
				return err
			}
			if i, err := session.Status(cmd.Context(), sp); err == nil {
				return fmt.Errorf("%s is already open, mounted at %s (theca close %s)", name, i.Mount, name)
			}
			ctx, stop := stopSignals(cmd.Context())
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, maxOpenWait)
			defer cancel()
			i, err := startDaemon(ctx, name, os.Stderr)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is open, mounted at %s\nclose it with: theca close %s\n", name, i.Mount, name)
			return nil
		},
	}
}

func closeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "close NAME",
		Short: "Unmount, commit and close an open container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sp, err := socketPath(args[0])
			if err != nil {
				return err
			}
			if err := session.Close(cmd.Context(), sp); err != nil {
				if errors.Is(err, session.ErrNotOpen) {
					return fmt.Errorf("%s is not open", args[0])
				}
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s closed\n", args[0])
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [NAME]",
		Short: "Say which profiles are open, and where they are mounted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := profileStore()
			if err != nil {
				return err
			}
			ps, err := st.List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATE\tMOUNT\tSINCE")
			for _, p := range ps {
				if len(args) == 1 && p.Name != args[0] {
					continue
				}
				sp, err := socketPath(p.Name)
				if err != nil {
					return err
				}
				i, err := session.Status(cmd.Context(), sp)
				if err != nil {
					fmt.Fprintf(w, "%s\tclosed\t-\t-\n", p.Name)
					continue
				}
				fmt.Fprintf(w, "%s\topen\t%s\t%s\n", p.Name, i.Mount, time.Unix(i.Since, 0).Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}
}

// ---- the background process ----

// spawnDaemon starts this program as `_serve NAME`, which inherits the
// terminal until the container is open (so the key's touch notice and a PIN
// prompt reach the person), then waits for its one-line report on a pipe.
func spawnDaemon(ctx context.Context, name string, stderr *os.File) (session.Info, error) {
	exe, err := executable()
	if err != nil {
		return session.Info{}, err
	}
	// The daemon is a new process: it gets the mode this one runs in.
	return session.StartAttached(ctx, exe, name, os.Stdin, stderr, "--mlock", memlock.Current().String())
}

// secretsOf turns a profile into the flags `theca serve` would have been given.
func secretsOf(p profile.Profile) secrets {
	s := secrets{
		passwordFrom: p.PasswordFrom,
		recoveryFrom: p.RecoveryFrom,
		pinFrom:      p.PINFrom,
		hint:         p.Hint,
		fido:         p.UsesKey(),
		device:       p.Device,
	}
	s.tpm.counter = p.Counter
	s.tpm.device = p.TPMDevice
	s.tpm.authFrom = p.TPMAuthFrom
	s.tpm.endorsementAuthFrom = p.TPMEndorsementFrom
	return s
}

// daemon is the unlocked container behind the socket.
type daemon struct {
	info session.Info
	sh   sharer
	c    *theca.Container
	f    *os.File

	once sync.Once
	done chan struct{}
	err  error
}

func (d *daemon) Status() session.Info { return d.info }

// Close unmounts, commits and wipes, once; every caller gets the same answer
// when it is done.
func (d *daemon) Close() error {
	d.once.Do(func() {
		d.err = closeBoth(d.c, d.f, d.sh.Stop())
		close(d.done)
	})
	<-d.done
	return d.err
}

func serveProfileCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "_serve NAME",
		Hidden: true,
		Short:  "The background process of `theca open` (not for people)",
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ready := readyFile()
			if ready == nil {
				return errors.New("_serve is started by `theca open`")
			}
			hardenProcess(cmd.ErrOrStderr()) // before a key exists
			defer ready.Close()
			err := onMainThread(func() error { return runDaemon(cmd, args[0], ready) })
			if err != nil {
				// Tell the parent, if it still listens; after the ready line
				// this is a second line nobody reads.
				session.Report(ready, session.Response{Error: err.Error()})
			}
			return err
		},
	}
}

func runDaemon(cmd *cobra.Command, name string, ready io.Writer) error {
	st, err := profileStore()
	if err != nil {
		return err
	}
	p, err := st.Get(name)
	if err != nil {
		return err
	}
	sp, err := socketPath(name)
	if err != nil {
		return err
	}
	release, err := lockFile(p.File)
	if err != nil {
		return err
	}
	defer release()
	s := secretsOf(p)
	c, f, err := open(cmd, p.File, &s, true)
	if err != nil {
		return err
	}
	ctx, stop := stopSignals(cmd.Context())
	defer stop()
	sh, err := startShare(ctx, c, share.Options{Addr: "127.0.0.1:0", Name: p.Share, Sync: p.Sync, Mount: true})
	if err != nil {
		if errors.Is(err, share.ErrNoFilesystem) {
			err = fmt.Errorf("%w (create one with --fs exfat)", err)
		}
		return closeBoth(c, f, err)
	}
	d := &daemon{sh: sh, c: c, f: f, done: make(chan struct{}), info: session.Info{
		Name: name, File: p.File, Mount: sh.MountPath(), URL: sh.URL(), Since: time.Now().Unix(), PID: os.Getpid(),
	}}
	srv, err := session.Listen(sp)
	if err != nil {
		return errors.Join(err, d.Close())
	}
	go srv.Serve(d)
	var locked <-chan string
	if p.CloseOnLock {
		var lerr error
		lockwatch.LogTo(cmd.ErrOrStderr())
		if locked, lerr = watchLock(ctx); lerr != nil {
			// Fail closed: a container that was to close when the screen
			// locks must not stay mounted with nothing watching. The
			// person who wants it anyway says so.
			srv.Shutdown()
			return errors.Join(fmt.Errorf("close-on-lock: %w; the container was closed again, not left mounted unprotected (open it without lock detection with --close-on-lock=false)", lerr), d.Close())
		}
	}
	if err := session.Report(ready, session.Response{OK: true, Info: &d.info}); err != nil {
		srv.Shutdown()
		return errors.Join(err, d.Close())
	}
	if err := detach(); err != nil {
		srv.Shutdown()
		return errors.Join(err, d.Close())
	}
	select {
	case <-ctx.Done():
	case <-sh.Done():
	case <-locked:
	case <-d.done:
	}
	err = d.Close()
	srv.Shutdown()
	return err
}
