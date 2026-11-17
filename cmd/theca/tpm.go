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

// hint turns the library's "missing counter" refusal into one that names the flag.
func (f *tpmFlags) hint(err error) error {
	if errors.Is(err, theca.ErrCounter) && f.counter == "" {
		return fmt.Errorf("%w: this container is bound to a TPM counter, give --counter tpm", err)
	}
	return err
}
