// Command theca creates, inspects and copies data in and out of Theca
// containers (docs/DESIGN.md). It does not mount anything.
//
// Secrets never travel in argv or the environment: the password and the
// recovery code are read from the terminal with echo off, from a file
// that only its owner can read (--password-file, --recovery-file), or from a
// secret manager by reference (--password-from, --recovery-from, --pin-from:
// keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT,
// keepassxc:URL or file:PATH).
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/go-authn/secretsource"
	"github.com/go-theca/theca"
	"github.com/go-theca/theca/fido2"
	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/memlock"
)

func enrollKeyCmd() *cobra.Command {
	var s secrets
	var require bool
	cmd := &cobra.Command{
		Use:   "enroll-key FILE",
		Short: "Pair the attached FIDO2 security key with the password (and the recovery code)",
		Long: "Pair the attached FIDO2 security key with the password, and with the\n" +
			"recovery code too when --recovery-from names it. The key makes one\n" +
			"discoverable credential and is touched twice: to register, then to confirm.\n" +
			"Nothing about the key is written into the container but its pairwise slots.\n\n" +
			"Pairing only ADDS a way in: under policy any the password alone (and the\n" +
			"recovery code alone) still open the container. enroll-key says which still\n" +
			"do, and the command that removes the password-only slot. --require does it\n" +
			"in the same run: after pairing, the key is touched once more to PROVE that\n" +
			"the password with the key opens the container, and only then is the\n" +
			"password-only slot removed (nothing is written if the proof fails). The\n" +
			"recovery code alone is NOT touched by --require: it stays the way in if the\n" +
			"key is lost, until you remove it with slots remove.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.OpenFile(args[0], os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			salt := make([]byte, format.SaltSize)
			if _, err := f.ReadAt(salt, 0); err != nil {
				return err
			}
			u, wipe, err := s.unlock(cmd)
			defer wipe()
			if err != nil {
				return err
			}
			if require && len(u.Password) == 0 {
				return errors.New("--require removes the password-only slot, so it needs the password: give --password-from REF")
			}
			// The partner factors, derived from the same secrets that open it.
			var partners []theca.Factor
			defer func() {
				for i := range partners {
					partners[i].Zeroize()
				}
			}()
			if len(u.Password) > 0 {
				pw, err := theca.PasswordFactor(s.hint, u.Password, salt)
				if err != nil {
					return err
				}
				partners = append(partners, pw)
			}
			if len(u.Recovery) > 0 {
				rc, err := theca.RecoveryFactor(u.Recovery)
				if err != nil {
					return err
				}
				partners = append(partners, rc)
			}
			c, err := s.openContainer(cmd, f, u)
			if err != nil {
				return err
			}
			dev, err := openFIDO(cmd.Context(), s.keyPIN(cmd), s.device)
			if err != nil {
				c.Close()
				return err
			}
			defer dev.Close()
			label := dev.Label()
			fmt.Fprintln(cmd.ErrOrStderr(), "Touch the security key twice when it blinks: to register it, then to confirm.")
			err = c.EnrollFIDO2(cmd.Context(), dev, partners...)
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: the key %s is paired with %d factor(s)\n", label, len(partners))
				err = afterEnroll(cmd, c, dev, &s, args[0], partners, require)
			}
			if cerr := c.Close(); err == nil {
				err = cerr
			}
			return err
		},
	}
	s.flags(cmd)
	s.recoveryFlag(cmd)
	s.pinFlag(cmd)
	cmd.Flags().BoolVar(&require, "require", false, "after pairing, prove the key opens the container, then remove the password-only slot: the key becomes mandatory with the password")
	return cmd
}

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	root := RootCmd()
	if err := root.Execute(); err != nil {
		// The library's errors already start with "theca:".
		msg := err.Error()
		if !strings.HasPrefix(msg, "theca: ") {
			msg = "theca: " + msg
		}
		fmt.Fprintln(root.ErrOrStderr(), msg)
		osExit(1)
	}
}

// The terminal, replaceable by tests.
var (
	isTerminal   = term.IsTerminal
	readPassword = term.ReadPassword
)

// readTerminal reads one secret from the terminal with echo off. Tests
// replace it.
var readTerminal = func(cmd *cobra.Command, prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return nil, errors.New("no terminal to ask for a secret: use --password-from or --recovery-from")
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	b, err := readPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

// maxSecretFile bounds what a secret file may hold.
const maxSecretFile = secretsource.MaxSize

func openRef(ctx context.Context, ref string) ([]byte, error) {
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// readRef resolves a secretsource reference (file:, keychain:,
// secretservice:); the bytes are the caller's to wipe. Tests replace it.
var readRef = openRef

// The write side of the same references, replaceable by tests.
var (
	storeSecret    = secretsource.Store
	generateSecret = secretsource.Generate
)

// readSecretFile reads a secret from a regular file that its owner alone
// can read or write, and strips one trailing newline.
func readSecretFile(path string) ([]byte, error) {
	return openRef(context.Background(), "file:"+path)
}

// secrets holds the flags shared by every command that opens a container.
// Each secret has a file flag and a manager flag (--X-from), exclusive.
type secrets struct {
	passwordFile string
	passwordFrom string
	recoveryFile string
	recoveryFrom string
	hint         int
	fido         bool
	pinFile      string
	pinFrom      string
	device       string
	tpm          tpmFlags
}

// fromHelp is the common tail of the --X-from help texts.
const fromHelp = " from a secret manager: keychain:SERVICE/ACCOUNT, secretservice:SERVICE/ACCOUNT, keepassxc:URL (the entry's URL field) or, on Linux, systemd-creds:NAME (a systemd credential); file:PATH still works but is deprecated"

// deprecateFile hides a secret file flag from the help and warns on standard
// error, naming the replacement, whenever it is used. (cobra's own
// MarkDeprecated prints on standard output when a command has an output
// writer, which would corrupt what create and export print.) No command here
// has a PreRun of its own, so the warning owns PreRunE.
func deprecateFile(cmd *cobra.Command, file, from string) {
	cmd.Flags().MarkHidden(file)
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		if c.Flags().Changed(file) {
			fmt.Fprintf(c.ErrOrStderr(), "Flag --%s is deprecated: a secret file beside the container's other factors defeats them; use --%s with keychain:, secretservice: or keepassxc:\n", file, from)
		}
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}

// warnFileRef warns when a --X-from reference is a file: one.
func warnFileRef(cmd *cobra.Command, flag, ref string) {
	if r, err := secretsource.Parse(ref); err == nil && r.Scheme == "file" {
		fmt.Fprintf(cmd.ErrOrStderr(), "Flag --%s: a file: reference is deprecated, use keychain:, secretservice: or keepassxc:\n", flag)
	}
}

// passwordGiven reports whether the password comes from a file or a manager.
func (s *secrets) passwordGiven() bool { return s.passwordFile != "" || s.passwordFrom != "" }

// printCode writes a secret and a newline as bytes: Fprintln of a []byte would
// print numbers, and Fprintf("%s") would copy it into fmt's pooled buffer.
// A failed write is not reported: the stream is the terminal, and the code
// has no other copy to fall back to either way.
func printCode(w io.Writer, code []byte) {
	_, _ = w.Write(code)
	_, _ = io.WriteString(w, "\n")
}

// recoveryGiven reports whether the recovery code comes from a file or a manager.
func (s *secrets) recoveryGiven() bool { return s.recoveryFile != "" || s.recoveryFrom != "" }

// source reads a secret from a file or a reference; ok is false when neither
// was given.
func (s *secrets) source(cmd *cobra.Command, name, file, from string) (b []byte, ok bool, err error) {
	switch {
	case from != "":
		warnFileRef(cmd, name+"-from", from)
		b, err = readRef(cmd.Context(), from)
		return b, true, err
	case file != "":
		b, err = readSecretFile(file)
		return b, true, err
	}
	return nil, false, nil
}

func (s *secrets) flags(cmd *cobra.Command) {
	s.tpm.flags(cmd)
	cmd.Flags().StringVar(&s.passwordFile, "password-file", "", "read the password from this file (mode 0600 or stricter) instead of the terminal")
	cmd.Flags().StringVar(&s.passwordFrom, "password-from", "", "read the password"+fromHelp)
	cmd.MarkFlagsMutuallyExclusive("password-file", "password-from")
	deprecateFile(cmd, "password-file", "password-from")
	cmd.Flags().IntVar(&s.hint, "hint", 0, "Argon2id profile the password was created with: 0, 1 or 2 (DESIGN 6.1)")
}

func (s *secrets) unlockFlags(cmd *cobra.Command) {
	s.flags(cmd)
	s.recoveryFlag(cmd)
	cmd.Flags().BoolVar(&s.fido, "fido2", false, "also use the attached FIDO2 security key (it pairs with the password or the recovery code)")
	s.pinFlag(cmd)
}

func (s *secrets) recoveryFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.recoveryFile, "recovery-file", "", "also present the recovery code read from this file (mode 0600 or stricter)")
	cmd.Flags().StringVar(&s.recoveryFrom, "recovery-from", "", "also present the recovery code read"+fromHelp)
	cmd.MarkFlagsMutuallyExclusive("recovery-file", "recovery-from")
	deprecateFile(cmd, "recovery-file", "recovery-from")
}

// pinFlag adds the flags of the security-key commands: the PIN source and
// which key (--device), because with several keys attached the first is not a
// choice.
func (s *secrets) pinFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.device, "device", "", "use the security key with this `ID` or name (fido list prints them); with several attached and none named, touch the one to use")
	cmd.Flags().StringVar(&s.pinFile, "pin-file", "", "read the security key's PIN from this file (mode 0600 or stricter) instead of the terminal; unused by a key with a fingerprint")
	cmd.Flags().StringVar(&s.pinFrom, "pin-from", "", "read the security key's PIN"+fromHelp+"; unused by a key with a fingerprint")
	cmd.MarkFlagsMutuallyExclusive("pin-file", "pin-from")
	deprecateFile(cmd, "pin-file", "pin-from")
}

// keyPIN returns the function the key asks for its PIN through, only when
// it has no built-in verification.
func (s *secrets) keyPIN(cmd *cobra.Command) func() ([]byte, error) {
	return func() ([]byte, error) {
		b, ok, err := s.source(cmd, "pin", s.pinFile, s.pinFrom)
		if !ok {
			b, err = readTerminal(cmd, "Security key PIN: ")
		}
		return b, err // the key layer wipes it after use
	}
}

// fidoDevice is a FIDO2 factor that must be released.
type fidoDevice interface {
	theca.FIDO2
	Close() error
	// Label names the key (product, id, serial) for a person.
	Label() string
}

// openFIDO opens the security key the device ID names (or the one touched,
// among several); tests replace it.
var openFIDO = func(ctx context.Context, pin func() ([]byte, error), device string) (fidoDevice, error) {
	return fido2.Open(ctx, pin, fido2.WithNotice(printNotice), fido2.WithDevice(device))
}

// printNotice shows what the key layer does on the person's behalf (a
// fingerprint retry, the fall back to the PIN).
func printNotice(m string) { fmt.Fprintln(os.Stderr, m) }

func (s *secrets) password(cmd *cobra.Command, prompt string) ([]byte, error) {
	if b, ok, err := s.source(cmd, "password", s.passwordFile, s.passwordFrom); ok {
		return b, err
	}
	return readTerminal(cmd, prompt)
}

// unlock gathers the factors: the password (file or terminal) unless only a
// recovery file was given, and the recovery code if a file names it.
func (s *secrets) unlock(cmd *cobra.Command) (theca.Unlock, func(), error) {
	u := theca.Unlock{Hint: s.hint}
	var dev fidoDevice
	wipe := func() {
		clear(u.Password)
		clear(u.Recovery)
		if dev != nil {
			dev.Close()
		}
	}
	if s.fido {
		var err error
		if dev, err = openFIDO(cmd.Context(), s.keyPIN(cmd), s.device); err != nil {
			return u, wipe, err
		}
		u.FIDO = dev
		fmt.Fprintln(cmd.ErrOrStderr(), "Touch the security key when it blinks.")
	}
	if rc, ok, err := s.source(cmd, "recovery", s.recoveryFile, s.recoveryFrom); ok {
		if err != nil {
			return u, wipe, err
		}
		u.Recovery = rc
	}
	if s.passwordGiven() || !s.recoveryGiven() {
		pw, err := s.password(cmd, "Password: ")
		if err != nil {
			return u, wipe, err
		}
		u.Password = pw
	}
	return u, wipe, nil
}

// open unlocks path, read-only or read-write, and states the rollback
// status, as DESIGN 5.4 requires at every mount.
func open(cmd *cobra.Command, path string, s *secrets, write bool) (*theca.Container, *os.File, error) {
	flag := os.O_RDONLY
	// A mount under a counter rebinds the header to the counter's next value
	// (DESIGN 5.4), so it writes, even for info or export.
	if write || s.tpm.counter != "" {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, nil, err
	}
	u, wipe, err := s.unlock(cmd)
	defer wipe()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	c, err := s.openContainer(cmd, f, u)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !c.Info().RollbackProtected {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: this container has no rollback counter: an older copy of it would be accepted")
	} else if c.Info().CounterTPM == nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+unpinned)
	}
	return c, f, nil
}

// withStored says, when create fails after --password-to stored the password,
// that the stored password belongs to no container.
func withStored(err error, passwordTo string) error {
	if passwordTo == "" {
		return err
	}
	return fmt.Errorf("%w (the password stays stored in %s, for no container; use --replace to overwrite it next time)", err, passwordTo)
}

func closeBoth(c *theca.Container, f *os.File, err error) error {
	if cerr := c.Close(); err == nil {
		err = cerr
	}
	if ferr := f.Close(); err == nil {
		err = ferr
	}
	return err
}

// parseSize reads a byte count with an optional K, M, G or T suffix (powers
// of 1024).
func parseSize(s string) (uint64, error) {
	mult := uint64(1)
	t := strings.ToUpper(strings.TrimSpace(s))
	for i, suf := range []string{"K", "M", "G", "T"} {
		if strings.HasSuffix(t, suf) {
			mult = 1 << (10 * (i + 1))
			t = strings.TrimSuffix(t, suf)
			break
		}
	}
	n, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	if n > ^uint64(0)/mult {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return n * mult, nil
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "theca",
		Short:         "Create and use Theca encrypted containers",
		Long:          "Create and use Theca encrypted containers (docs/DESIGN.md).\n\nSecrets are read from the terminal with echo off, or from owner-only files.\nThey are never accepted as arguments or environment variables.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var mlockMode string
	root.PersistentFlags().StringVar(&mlockMode, "mlock", "auto", "keep the pages that hold keys out of swap: auto (try, say once if refused), off, or required (refuse to run if the system refuses)")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		m, err := memlock.ParseMode(mlockMode)
		if err != nil {
			return err
		}
		memlock.SetMode(m)
		w := cmd.ErrOrStderr()
		memlock.SetReporter(func(err error) {
			fmt.Fprintf(w, "warning: %v: the keys may be written to swap (raise RLIMIT_MEMLOCK, or use --mlock=required to refuse to run)\n", err)
		})
		return nil
	}
	root.AddCommand(createCmd(), infoCmd(), verifyCmd(), exportCmd(), importCmd(), enrollKeyCmd(), serveCmd(), slotsCmd(), counterCmd(),
		journalCmd(), profileCmd(), openCmd(), closeCmd(), statusCmd(), serveProfileCmd())
	return root
}

func createCmd() *cobra.Command {
	var s secrets
	var size, policy, fsKind, passwordTo, recoveryTo string
	var journal uint32
	var generate int
	var replace bool
	cmd := &cobra.Command{
		Use:   "create FILE",
		Short: "Create a new container; prints the recovery code once (or stores it with --recovery-to)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if fsKind != "" && fsKind != "exfat" {
				return fmt.Errorf("--fs %q: want exfat (or nothing for a raw volume)", fsKind)
			}
			n, err := parseSize(size)
			if err != nil {
				return err
			}
			if n == 0 || n%theca.SectorSize != 0 {
				return fmt.Errorf("--size must be a positive multiple of %d bytes", theca.SectorSize)
			}
			var pol theca.Policy
			switch policy {
			case "any":
				pol = theca.PolicyAny
			case "2of3":
				pol = theca.PolicyTwoOfThree
			default:
				return fmt.Errorf("--policy %q: want any or 2of3", policy)
			}
			gen := cmd.Flags().Changed("generate")
			if gen && passwordTo == "" {
				return errors.New("--generate needs --password-to: a password nobody could read back would lock the container forever")
			}
			var pw []byte
			if gen {
				pw, err = generateSecret(generate)
			} else {
				pw, err = s.password(cmd, "New password: ")
			}
			if err != nil {
				return err
			}
			defer clear(pw)
			if !s.passwordGiven() && !gen {
				again, err := readTerminal(cmd, "Repeat password: ")
				if err != nil {
					return err
				}
				same := subtle.ConstantTimeCompare(again, pw) == 1
				clear(again)
				if !same {
					return errors.New("the passwords differ")
				}
			}
			// The password is stored BEFORE the container exists: when the
			// store fails nothing was created, and when creating fails later
			// the worst left behind is a stored password for no container.
			if passwordTo != "" {
				if err := storeSecret(cmd.Context(), passwordTo, pw, secretsource.StoreOptions{Replace: replace}); err != nil {
					return fmt.Errorf("the password was not stored in %s, so no container was created: %w", passwordTo, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Password stored in %s (not printed).\n", passwordTo)
			}
			f, err := os.OpenFile(args[0], os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return withStored(err, passwordTo)
			}
			ctr, mkCounter, undo, err := s.tpm.newCounter(cmd.Context())
			if err != nil {
				f.Close()
				os.Remove(args[0])
				return withStored(err, passwordTo)
			}
			c, code, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
				Sectors: n / theca.SectorSize, JournalEntries: journal, Hint: s.hint,
				Password: pw, Policy: pol, Counter: ctr, NewCounter: mkCounter,
			})
			err = s.tpm.hint(err)
			if err == nil {
				if err = formatFS(c, fsKind); err != nil {
					c.Close()
				}
			}
			if err != nil {
				undo()
				f.Close()
				os.Remove(args[0])
				return withStored(err, passwordTo)
			}
			// The code is printed even if closing fails: the container is
			// formatted and the code is the only copy there will ever be.
			// code is bytes, wiped when this command is done with it; it is
			// written to the stream as bytes, never through a string.
			defer clear(code)
			var storeErr error
			if recoveryTo != "" {
				storeErr = storeSecret(cmd.Context(), recoveryTo, code, secretsource.StoreOptions{Replace: replace})
			}
			switch {
			case recoveryTo != "" && storeErr == nil:
				fmt.Fprintf(cmd.ErrOrStderr(), "Recovery code stored in %s (not printed).\n", recoveryTo)
			case storeErr != nil:
				// The store failed: the code is printed after all, because the
				// container exists and this is the only copy there will ever be.
				fmt.Fprintf(cmd.ErrOrStderr(), "The recovery code could not be stored in %s (%v); it is printed here, the only copy:\n", recoveryTo, storeErr)
				printCode(cmd.OutOrStdout(), code)
			default:
				fmt.Fprintln(cmd.ErrOrStderr(), "Recovery code (shown once, never stored; write it down):")
				printCode(cmd.OutOrStdout(), code)
			}
			if c.Info().RollbackProtected {
				fmt.Fprintf(cmd.ErrOrStderr(), "rollback counter: TPM NV index %#08x; give --counter tpm to every command that opens this container\n", c.Info().CounterHandle)
				fmt.Fprintln(cmd.ErrOrStderr(), identityLine(c.Info()))
				fmt.Fprintln(cmd.ErrOrStderr(), authLine(c.Info()))
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: no rollback counter: an older copy of this container would be accepted")
			}
			return closeBoth(c, f, storeErr)
		},
	}
	s.flags(cmd)
	cmd.Flags().StringVar(&passwordTo, "password-to", "", "store the new password in a secret manager (keychain:, secretservice:, keepassxc:URL) BEFORE creating the container; the terminal's typed-twice password, or --generate")
	cmd.Flags().StringVar(&recoveryTo, "recovery-to", "", "store the recovery code there instead of printing it (if that fails it is printed after all)")
	cmd.Flags().IntVar(&generate, "generate", 0, "draw N random characters as the password (needs --password-to)")
	cmd.Flags().BoolVar(&replace, "replace", false, "overwrite an existing entry at --password-to / --recovery-to")
	cmd.MarkFlagsMutuallyExclusive("password-to", "password-file")
	cmd.MarkFlagsMutuallyExclusive("password-to", "password-from")
	cmd.MarkFlagsMutuallyExclusive("generate", "password-file")
	cmd.MarkFlagsMutuallyExclusive("generate", "password-from")
	cmd.Flags().StringVar(&size, "size", "", "logical size, a multiple of 4096 bytes (suffixes K, M, G, T)")
	cmd.Flags().StringVar(&policy, "policy", "any", "any: password or recovery code alone opens it; 2of3: both are needed")
	cmd.Flags().StringVar(&fsKind, "fs", "", "format the volume with this filesystem: exfat (serve needs one); empty: a raw volume")
	cmd.Flags().Uint32Var(&journal, "journal", 0, "journal entries: the most one commit holds (0: one per 16 sectors, from 64 to 4096)")
	cmd.MarkFlagRequired("size")
	return cmd
}

func infoCmd() *cobra.Command {
	var s secrets
	cmd := &cobra.Command{
		Use:   "info FILE",
		Short: "Unlock a container and describe it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, f, err := open(cmd, args[0], &s, false)
			if err != nil {
				return err
			}
			i := c.Info()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "size:               %d bytes (%d sectors)\n", i.Size, i.Sectors)
			fmt.Fprintf(out, "epoch:              %d\n", i.Epoch)
			fmt.Fprintf(out, "slots used:         %d of 16\n", i.SlotsUsed)
			fmt.Fprintf(out, "journal entries:    %d\n", i.JournalEntries)
			if i.RollbackProtected {
				fmt.Fprintf(out, "rollback protected: true (TPM NV counter %#08x: an older copy of this container is refused)\n", i.CounterHandle)
				fmt.Fprintln(out, identityLine(i))
				fmt.Fprintln(out, authLine(i))
			} else {
				fmt.Fprintln(out, "rollback protected: false (no counter: an older copy of this container would be accepted)")
			}
			return closeBoth(c, f, nil)
		},
	}
	s.unlockFlags(cmd)
	return cmd
}

func verifyCmd() *cobra.Command {
	var s secrets
	cmd := &cobra.Command{
		Use:   "verify FILE",
		Short: "Authenticate every sector, metadata block and tree node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, f, err := open(cmd, args[0], &s, false)
			if err != nil {
				return err
			}
			n, err := c.Verify()
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: %d sectors verified\n", n)
			}
			return closeBoth(c, f, err)
		},
	}
	s.unlockFlags(cmd)
	return cmd
}

func exportCmd() *cobra.Command {
	var s secrets
	var off, length int64
	cmd := &cobra.Command{
		Use:   "export FILE",
		Short: "Write the decrypted volume (or a range of it) to standard output",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, f, err := open(cmd, args[0], &s, false)
			if err != nil {
				return err
			}
			if length == -1 {
				length = c.Size() - off
			}
			if off < 0 || off > c.Size() || length < 0 || length > c.Size()-off {
				return closeBoth(c, f, theca.ErrRange)
			}
			_, err = io.Copy(cmd.OutOrStdout(), io.NewSectionReader(c, off, length))
			return closeBoth(c, f, err)
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().Int64Var(&off, "offset", 0, "first byte")
	cmd.Flags().Int64Var(&length, "length", -1, "number of bytes (-1: to the end)")
	return cmd
}

func importCmd() *cobra.Command {
	var s secrets
	var off int64
	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Write standard input into the volume at an offset, then commit",
		Long: "Write standard input into the volume at an offset, then commit.\n\n" +
			"Input running past the end of the volume is refused. The copy is not one\n" +
			"atomic transaction: on any error, the bytes written before it are kept.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !s.passwordGiven() && !s.recoveryGiven() {
				return errors.New("import reads the data from standard input: give --password-from or --recovery-from")
			}
			c, f, err := open(cmd, args[0], &s, true)
			if err != nil {
				return err
			}
			if off < 0 || off > c.Size() {
				return closeBoth(c, f, theca.ErrRange)
			}
			// The container refuses a write past its end (ErrRange). Copying
			// is not atomic (DESIGN 19, I12): what was written before an
			// error stays, and is committed when the container closes.
			n, err := io.Copy(io.NewOffsetWriter(c, off), cmd.InOrStdin())
			if err == nil {
				err = c.Sync()
			}
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: %d bytes written at %d\n", n, off)
			}
			return closeBoth(c, f, err)
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().Int64Var(&off, "offset", 0, "first byte")
	return cmd
}
