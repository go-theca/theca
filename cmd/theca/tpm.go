package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/tpmcounter"
)

// tpmCounter is a counter that can also be deleted again.
type tpmCounter interface {
	theca.Counter
	Destroy() error
}

// The TPM, replaceable by tests (which use a fake counter).
var (
	createCounter = func(o tpmcounter.Options) (tpmCounter, error) {
		c, err := tpmcounter.Create(o)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	openCounter = func(o tpmcounter.Options) (theca.Counter, error) {
		c, err := tpmcounter.Open(o)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
)

// tpmFlags are the flags of the rollback counter (DESIGN 5.4).
type tpmFlags struct {
	counter        string
	device         string
	handle         uint32
	authFile       string
	ownerAuthFile  string
	acceptRollback bool
}

func (f *tpmFlags) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.counter, "counter", "", "rollback counter: tpm (a TPM 2.0 NV counter) or empty for none; create makes one, the other commands must be given it again")
	cmd.Flags().StringVar(&f.device, "tpm-device", "", "TPM device: a path, or unix:SOCKET for a software TPM (default /dev/tpmrm0 on Linux)")
	cmd.Flags().Uint32Var(&f.handle, "tpm-handle", 0, "create: NV index of the new counter (0: the first free one from 0x01500000)")
	cmd.Flags().StringVar(&f.authFile, "tpm-auth-file", "", "file holding the counter's authValue, at most 32 bytes (mode 0600 or stricter); empty authValue if absent")
	cmd.Flags().StringVar(&f.ownerAuthFile, "tpm-owner-auth-file", "", "create: file holding the TPM owner password (mode 0600 or stricter); empty if absent")
	cmd.Flags().BoolVar(&f.acceptRollback, "accept-rollback", false, "rebind a container older than the counter to the counter's value (loud: an old copy is accepted as current)")
}

// on reports whether a TPM counter was asked for.
func (f *tpmFlags) on() (bool, error) {
	switch f.counter {
	case "":
		return false, nil
	case "tpm":
		return true, nil
	}
	return false, fmt.Errorf("--counter %q: want tpm", f.counter)
}

// options builds the tpmcounter options; owner says whether the owner password
// is needed (create).
func (f *tpmFlags) options(owner bool) (tpmcounter.Options, func(), error) {
	o := tpmcounter.Options{Device: f.device, Handle: f.handle}
	wipe := func() { clear(o.Auth); clear(o.OwnerAuth) }
	var err error
	if f.authFile != "" {
		if o.Auth, err = readSecretFile(f.authFile); err != nil {
			return o, wipe, err
		}
	}
	if owner && f.ownerAuthFile != "" {
		if o.OwnerAuth, err = readSecretFile(f.ownerAuthFile); err != nil {
			return o, wipe, err
		}
	}
	return o, wipe, nil
}

// openOptions are the theca.OpenOptions for an existing container. The
// counter is found from the header once it is authenticated, so only the TPM
// and its credentials are named here. wipe clears the credentials.
func (f *tpmFlags) openOptions() (theca.OpenOptions, func(), error) {
	on, err := f.on()
	if err != nil || !on {
		return theca.OpenOptions{AcceptRollback: f.acceptRollback}, func() {}, err
	}
	o, wipe, err := f.options(false)
	if err != nil {
		wipe()
		return theca.OpenOptions{}, func() {}, err
	}
	return theca.OpenOptions{
		AcceptRollback: f.acceptRollback,
		CounterFor: func(h uint32, _ []byte) (theca.Counter, error) {
			o.Handle = h
			return openCounter(o)
		},
	}, wipe, nil
}

// newCounter creates the counter for a new container, or returns nil when none
// was asked for. undo deletes it again if the container cannot be made.
func (f *tpmFlags) newCounter() (ctr theca.Counter, undo func(), err error) {
	undo = func() {}
	on, err := f.on()
	if err != nil || !on {
		return nil, undo, err
	}
	o, wipe, err := f.options(true)
	if err != nil {
		wipe()
		return nil, undo, err
	}
	c, err := createCounter(o)
	if err != nil {
		wipe()
		return nil, undo, err
	}
	return c, func() { c.Destroy(); wipe() }, nil
}

// openContainer is theca.Open with the counter flags applied.
func (s *secrets) openContainer(cmd *cobra.Command, f *os.File, u theca.Unlock) (*theca.Container, error) {
	oo, wipe, err := s.tpm.openOptions()
	defer wipe()
	if err != nil {
		return nil, err
	}
	if oo.AcceptRollback {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: --accept-rollback: an older copy of this container will be accepted as current")
	}
	c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, oo)
	if err != nil {
		return nil, s.tpm.hint(err)
	}
	return c, nil
}

// recovery is the sentence that names the way back when the counter is gone.
const recovery = "if the counter was deleted or the TPM was cleared or replaced, " +
	"`theca counter rebind FILE --counter tpm` (with the owner password, and the factors that open the container) binds it to a new counter; rollback protection then restarts from that moment"

// hint turns the library's counter refusals into ones that name the flag or
// the recovery.
func (f *tpmFlags) hint(err error) error {
	switch {
	case errors.Is(err, theca.ErrCounter) && f.counter == "":
		return fmt.Errorf("%w: this container is bound to a TPM counter, give --counter tpm", err)
	case errors.Is(err, tpmcounter.ErrNoCounter), errors.Is(err, tpmcounter.ErrNotCounter), errors.Is(err, theca.ErrCounter):
		return fmt.Errorf("%w: %s", err, recovery)
	}
	return err
}

// counterCmd is `theca counter`, the recovery commands for the rollback counter.
func counterCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "counter",
		Short: "Recover the rollback counter of a container",
	}
	root.AddCommand(rebindCmd())
	return root
}

func rebindCmd() *cobra.Command {
	var s secrets
	cmd := &cobra.Command{
		Use:   "rebind FILE",
		Short: "Bind a container to a NEW TPM counter (the old one is gone)",
		Long: "Bind the container to a new TPM counter, when the old one was deleted (the NV\n" +
			"index undefined, the TPM cleared or replaced) or when you want another.\n" +
			"It needs the factors that open the container and the TPM owner password\n" +
			"(--tpm-owner-auth-file). The new counter is made at the handle the container\n" +
			"records when that handle is free, otherwise at the first free one.\n\n" +
			"Rollback protection restarts from now: nothing is checked against the old\n" +
			"counter, so a copy of the container made earlier is judged by the new one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			on, err := s.tpm.on()
			if err != nil {
				return err
			}
			if !on {
				return errors.New("counter rebind needs --counter tpm")
			}
			o, wipeOpts, err := s.tpm.options(true)
			defer wipeOpts()
			if err != nil {
				return err
			}
			f, err := os.OpenFile(args[0], os.O_RDWR, 0)
			if err != nil {
				return err
			}
			u, wipe, err := s.unlock(cmd)
			defer wipe()
			if err != nil {
				f.Close()
				return err
			}
			var made tpmCounter
			oo := theca.OpenOptions{RebindFor: func(h uint32, _ []byte) (theca.Counter, error) {
				try := o
				if try.Handle == 0 {
					try.Handle = h // the recorded handle, if it is free
				}
				c, err := createCounter(try)
				if err != nil && o.Handle == 0 && try.Handle != 0 {
					try.Handle = 0 // taken: the first free one
					c, err = createCounter(try)
				}
				if err != nil {
					return nil, err
				}
				made = c
				return c, nil
			}}
			c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, oo)
			if err != nil {
				if made != nil {
					made.Destroy() // the container was not rebound: do not leave the index behind
				}
				f.Close()
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: the container is now bound to a NEW TPM counter, NV index %#08x. "+
				"Rollback protection restarts from now: an older copy is not checked against the old counter, "+
				"and the old counter, if it still exists, is not deleted. Give --counter tpm to every command that opens this container.\n",
				c.Info().CounterHandle)
			return closeBoth(c, f, nil)
		},
	}
	s.unlockFlags(cmd)
	return cmd
}
