package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/go-authn/secretsource"
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

// removeCounter deletes the counter at o.Handle under the owner password. It
// reports whether there was one: an index that is absent, or is not a theca
// counter, is left alone. Replaceable by tests.
var removeCounter = func(o tpmcounter.Options) (bool, error) {
	c, err := tpmcounter.Open(o)
	if errors.Is(err, tpmcounter.ErrNoCounter) || errors.Is(err, tpmcounter.ErrNotCounter) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, c.Destroy()
}

// tpmFlags are the flags of the rollback counter (DESIGN 5.4).
type tpmFlags struct {
	counter             string
	device              string
	handle              uint32
	authFile            string
	authFrom            string
	ownerAuthFile       string
	ownerAuthFrom       string
	endorsementAuthFrom string
	acceptRollback      bool
}

// tpmFromHelp is the tail of the help of the secret-manager-only TPM flags.
const tpmFromHelp = " from a secret manager: keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT or keepassxc:URL (a file: reference is refused: a password file beside the hardware keys defeats them)"

func (f *tpmFlags) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.counter, "counter", "", "rollback counter: tpm (a TPM 2.0 NV counter) or empty for none; create makes one, the other commands must be given it again")
	cmd.Flags().StringVar(&f.device, "tpm-device", "", "TPM device: a path, or unix:SOCKET for a software TPM (default /dev/tpmrm0 on Linux)")
	cmd.Flags().Uint32Var(&f.handle, "tpm-handle", 0, "create: NV index of the new counter (0: the first free one from 0x01500000)")
	cmd.Flags().StringVar(&f.authFile, "tpm-auth-file", "", "file holding the counter's authValue, at most 32 bytes (mode 0600 or stricter); DEPRECATED, see --tpm-auth-from. With neither flag, a NEW counter's authValue is derived from the container's master key (nothing to store); a counter made earlier with a stored authValue needs its flag at every mount")
	cmd.Flags().StringVar(&f.authFrom, "tpm-auth-from", "", "the counter's authValue, at most 32 bytes,"+tpmFromHelp)
	cmd.Flags().StringVar(&f.ownerAuthFile, "tpm-owner-auth-file", "", "create, counter rebind: file holding the TPM owner password (mode 0600 or stricter); empty if absent; DEPRECATED, see --tpm-owner-auth-from")
	cmd.Flags().StringVar(&f.ownerAuthFrom, "tpm-owner-auth-from", "", "create, counter rebind: the TPM owner password"+tpmFromHelp)
	cmd.Flags().StringVar(&f.endorsementAuthFrom, "tpm-endorsement-auth-from", "", "the TPM's endorsement hierarchy password, empty if the TPM has none, needed at create, counter rebind and EVERY mount to name the TPM (its endorsement key)"+tpmFromHelp+
		". A wrong password is refused with TPM_RC_BAD_AUTH and does NOT count toward the TPM's dictionary-attack lockout: the authValue of a hierarchy is not DA protected (TCG TPM 2.0 Part 1 rev 1.59, 19.8.1), unlike lockoutAuth")
	cmd.Flags().BoolVar(&f.acceptRollback, "accept-rollback", false, "rebind a container older than the counter to the counter's value (loud: an old copy is accepted as current)")
	cmd.MarkFlagsMutuallyExclusive("tpm-auth-file", "tpm-auth-from")
	cmd.MarkFlagsMutuallyExclusive("tpm-owner-auth-file", "tpm-owner-auth-from")
	deprecateFile(cmd, "tpm-auth-file", "tpm-auth-from")
	deprecateFile(cmd, "tpm-owner-auth-file", "tpm-owner-auth-from")
}

// explicitAuth reports whether the counter's authValue is given by the user
// (a file or a manager) rather than derived from the container's master key.
func (f *tpmFlags) explicitAuth() bool { return f.authFile != "" || f.authFrom != "" }

// readManager reads a secret that must come from a secret manager: a file:
// reference is refused (the flag exists so that no password file does).
func readManager(ctx context.Context, flag, ref string) ([]byte, error) {
	r, err := secretsource.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flag, err)
	}
	if r.Scheme == "file" {
		return nil, fmt.Errorf("--%s: a file: reference is refused, use keychain:, secretservice: or keepassxc:", flag)
	}
	return readRef(ctx, ref)
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
func (f *tpmFlags) options(ctx context.Context, owner bool) (tpmcounter.Options, func(), error) {
	o := tpmcounter.Options{Device: f.device, Handle: f.handle}
	wipe := func() { clear(o.Auth); clear(o.OwnerAuth); clear(o.EndorsementAuth) }
	var err error
	switch {
	case f.authFrom != "":
		o.Auth, err = readManager(ctx, "tpm-auth-from", f.authFrom)
	case f.authFile != "":
		o.Auth, err = readSecretFile(f.authFile)
	}
	if err != nil {
		return o, wipe, err
	}
	if owner {
		switch {
		case f.ownerAuthFrom != "":
			o.OwnerAuth, err = readManager(ctx, "tpm-owner-auth-from", f.ownerAuthFrom)
		case f.ownerAuthFile != "":
			o.OwnerAuth, err = readSecretFile(f.ownerAuthFile)
		}
		if err != nil {
			return o, wipe, err
		}
	}
	if f.endorsementAuthFrom != "" {
		if o.EndorsementAuth, err = readManager(ctx, "tpm-endorsement-auth-from", f.endorsementAuthFrom); err != nil {
			return o, wipe, err
		}
	}
	return o, wipe, nil
}

// withAuth is o with the derived authValue of a counter; the copy is the
// counter's, the caller's slice is wiped when the callback returns.
func withAuth(o tpmcounter.Options, auth []byte) tpmcounter.Options {
	o.Auth = append([]byte(nil), auth...)
	return o
}

// openOptions are the theca.OpenOptions for an existing container. The
// counter is found from the header once it is authenticated, so only the TPM
// and its credentials are named here. wipe clears the credentials.
func (f *tpmFlags) openOptions(ctx context.Context) (theca.OpenOptions, func(), error) {
	on, err := f.on()
	if err != nil || !on {
		return theca.OpenOptions{AcceptRollback: f.acceptRollback}, func() {}, err
	}
	o, wipe, err := f.options(ctx, false)
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
		CounterDerived: func(h uint32, _, auth []byte) (theca.Counter, error) {
			d := withAuth(o, auth)
			d.Handle = h
			return openCounter(d)
		},
	}, wipe, nil
}

// newCounter creates the counter for a new container, or returns nil when none
// was asked for. undo deletes it again if the container cannot be made.
//
// With --tpm-auth-file or --tpm-auth-from the counter is made now, with that
// authValue (ctr). Without, the counter's authValue is derived from the
// container's master key, which does not exist yet: mk makes the counter once
// theca.Create has it (DESIGN 5.4.2).
func (f *tpmFlags) newCounter(ctx context.Context) (ctr theca.Counter, mk func([]byte) (theca.Counter, error), undo func(), err error) {
	undo = func() {}
	on, err := f.on()
	if err != nil || !on {
		return nil, nil, undo, err
	}
	o, wipe, err := f.options(ctx, true)
	if err != nil {
		wipe()
		return nil, nil, undo, err
	}
	if !f.explicitAuth() {
		var made tpmCounter
		mk = func(auth []byte) (theca.Counter, error) {
			c, err := createCounter(withAuth(o, auth))
			if err != nil {
				return nil, err
			}
			made = c
			return c, nil
		}
		return nil, mk, func() {
			if made != nil {
				made.Destroy()
			}
			wipe()
		}, nil
	}
	c, err := createCounter(o)
	if err != nil {
		wipe()
		return nil, nil, undo, err
	}
	return c, nil, func() { c.Destroy(); wipe() }, nil
}

// openContainer is theca.Open with the counter flags applied.
func (s *secrets) openContainer(cmd *cobra.Command, f *os.File, u theca.Unlock) (*theca.Container, error) {
	oo, wipe, err := s.tpm.openOptions(cmd.Context())
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
const recovery = "if the TPM was reset, cleared or replaced, or the counter deleted, " +
	"`theca counter rebind FILE --counter tpm` (with the owner password, and the factors that open the container) binds it to a new counter and deletes the old one if it is still there; " +
	"rollback protection then restarts from that moment. An OLD COPY of this container also shows this message: do not rebind to open an old copy"

// unpinned is the warning for a container made before the TPM identity was
// pinned: it still opens, as before.
const unpinned = "this container's rollback counter is not pinned to a TPM identity (it was made by an older theca): " +
	"a counter that another TPM defines at the same handle would be accepted. " +
	"`theca counter rebind FILE --counter tpm` pins this TPM, with the owner password and the factors that open the container; " +
	"it replaces the counter, so rollback protection restarts from that moment"

// identityLine says which TPM the counter is pinned to, or that none is.
func identityLine(i theca.Info) string {
	if i.CounterTPM == nil {
		return "counter TPM identity: not pinned (" + unpinned + ")"
	}
	return "counter TPM identity: " + theca.ShortID(i.CounterTPM) + " (EK Name digest: a counter on another TPM is refused)"
}

// authLine says where the counter's authValue comes from.
func authLine(i theca.Info) string {
	if i.CounterDerivedAuth {
		return "counter authValue: derived from the container's master key (whoever unlocks the container can use the counter; nothing to store)"
	}
	return "counter authValue: given with --tpm-auth-from / --tpm-auth-file (or empty): give the same one to every command; `theca counter rebind` without them migrates to a derived one"
}

// identityRecovery names the way out of a refusal on identity.
const identityRecovery = "if this is a different TPM on purpose (the machine or the TPM was replaced, the TPM's endorsement seed was changed), " +
	"`theca counter rebind FILE --counter tpm` (with the owner password and the factors that open the container) binds it to a new counter on this TPM and pins this TPM; " +
	"rollback protection then restarts from that moment. If you did not replace the TPM, do NOT rebind: something other than your TPM is answering"

// hint turns the library's counter refusals into ones that name the flag or
// the recovery.
func (f *tpmFlags) hint(err error) error {
	switch {
	case errors.Is(err, tpmcounter.ErrEndorsementAuth):
		return fmt.Errorf("%w: this TPM has an endorsement hierarchy password: give --tpm-endorsement-auth-from REF with the right one "+
			"(a wrong password does not count toward the TPM's dictionary-attack lockout, TCG Part 1 rev 1.59, 19.8.1)", err)
	case errors.Is(err, theca.ErrCounterIdentity):
		return fmt.Errorf("%w: %s", err, identityRecovery)
	case errors.Is(err, theca.ErrCounterRequired):
		return fmt.Errorf("%w (--counter %s); to bind it to a counter, `theca counter rebind FILE --counter tpm`", err, f.counter)
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
			"(--tpm-owner-auth-from, or the deprecated --tpm-owner-auth-file) and, on a TPM\n" +
			"with an endorsement password, --tpm-endorsement-auth-from. The new counter is\n" +
			"made at the handle the container records when that handle is free, otherwise\n" +
			"at the first free one.\n\n" +
			"Without --tpm-auth-from / --tpm-auth-file the new counter's authValue is\n" +
			"DERIVED from the container's master key: nothing to store, and a container\n" +
			"whose counter had a stored authValue is migrated by rebinding without them.\n\n" +
			"Rollback protection restarts from now: nothing is checked against the old\n" +
			"counter, so a copy of the container made earlier is judged by the new one.\n\n" +
			"It also pins THIS TPM's identity in the container (a counter on another TPM\n" +
			"is refused from then on): use it to pin a container made by an older theca,\n" +
			"or after the TPM was replaced on purpose.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			on, err := s.tpm.on()
			if err != nil {
				return err
			}
			if !on {
				return errors.New("counter rebind needs --counter tpm")
			}
			o, wipeOpts, err := s.tpm.options(cmd.Context(), true)
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
			removed := false
			// rebindAt makes the new counter; auth is the derived authValue, nil
			// when the user gave one (--tpm-auth-file/-from, already in o).
			rebindAt := func(h uint32, auth []byte) (theca.Counter, error) {
				base := o
				if auth != nil {
					base = withAuth(o, auth)
				}
				// A healthy old counter must go first: it stays at its value, and a
				// copy of the container taken just before this command (old handle,
				// bound equal to that value) would still open with it, silently
				// undoing the rebind. Deleted, the copy finds no counter (or a
				// redefined one that starts higher) and is refused.
				if h != 0 {
					old := base
					old.Handle = h
					var err error
					if removed, err = removeCounter(old); err != nil {
						return nil, err
					}
				}
				try := base
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
			}
			var oo theca.OpenOptions
			if s.tpm.explicitAuth() {
				oo.RebindFor = func(h uint32, _ []byte) (theca.Counter, error) { return rebindAt(h, nil) }
			} else {
				oo.RebindDerived = func(h uint32, _, auth []byte) (theca.Counter, error) { return rebindAt(h, auth) }
			}
			c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, oo)
			if err != nil {
				if made != nil {
					made.Destroy() // the container was not rebound: do not leave the index behind
				}
				f.Close()
				return s.tpm.hint(err)
			}
			gone := "The old counter was already absent."
			if removed {
				gone = "The old counter was still there and has been DELETED, so a copy made before this command is refused."
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: the container is now bound to a NEW TPM counter, NV index %#08x. "+
				"Rollback protection restarts from now. %s Give --counter tpm to every command that opens this container.\n",
				c.Info().CounterHandle, gone)
			fmt.Fprintln(cmd.ErrOrStderr(), identityLine(c.Info()))
			fmt.Fprintln(cmd.ErrOrStderr(), authLine(c.Info()))
			return closeBoth(c, f, nil)
		},
	}
	s.unlockFlags(cmd)
	return cmd
}
