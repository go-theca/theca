// Command theca creates, inspects and copies data in and out of Theca
// containers (docs/DESIGN.md). It does not mount anything.
//
// Secrets never travel in argv or the environment: the password and the
// recovery code are read from the terminal with echo off, or from a file
// that only its owner can read (--password-file, --recovery-file).
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

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/fido2"
	"github.com/go-theca/theca/internal/format"
)

func enrollKeyCmd() *cobra.Command {
	var s secrets
	cmd := &cobra.Command{
		Use:   "enroll-key FILE",
		Short: "Pair the attached FIDO2 security key with the password (and the recovery code)",
		Long: "Pair the attached FIDO2 security key with the password, and with the\n" +
			"recovery code too when --recovery-file names it. The key makes one\n" +
			"discoverable credential and is touched twice: to register, then to confirm.\n" +
			"Nothing about the key is written into the container but its pairwise slots.",
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
			if u.Recovery != "" {
				rc, err := theca.RecoveryFactor(u.Recovery)
				if err != nil {
					return err
				}
				partners = append(partners, rc)
			}
			c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, theca.OpenOptions{})
			if err != nil {
				return err
			}
			dev, err := openFIDO(cmd.Context(), s.keyPIN(cmd))
			if err != nil {
				c.Close()
				return err
			}
			defer dev.Close()
			fmt.Fprintln(cmd.ErrOrStderr(), "Touch the security key twice when it blinks: to register it, then to confirm.")
			err = c.EnrollFIDO2(cmd.Context(), dev, partners...)
			if cerr := c.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok: the key is paired with %d factor(s)\n", len(partners))
			return nil
		},
	}
	s.flags(cmd)
	s.recoveryFlag(cmd)
	s.pinFlag(cmd)
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
		return nil, errors.New("no terminal to ask for a secret: use --password-file or --recovery-file")
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	b, err := readPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	return b, err
}

// maxSecretFile bounds what a secret file may hold.
const maxSecretFile = 4096

// readSecretFile reads a secret from a regular file that its owner alone
// can read or write, and strips one trailing newline.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Checked on the open descriptor, not the path, so the file cannot be
	// swapped between the check and the read.
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s: not a regular file", path)
	}
	if err == nil && st.Mode().Perm()&0o077 != 0 {
		err = fmt.Errorf("%s: mode %04o, must not be readable or writable by group or others", path, st.Mode().Perm())
	}
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err == nil && len(b) > maxSecretFile {
		err = fmt.Errorf("%s: longer than %d bytes", path, maxSecretFile)
	}
	if err != nil {
		clear(b)
		return nil, err
	}
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
		if n > 0 && b[n-1] == '\r' {
			n--
		}
	}
	return b[:n], nil
}

// secrets holds the flags shared by every command that opens a container.
type secrets struct {
	passwordFile string
	recoveryFile string
	hint         int
	fido         bool
	pinFile      string
}

func (s *secrets) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.passwordFile, "password-file", "", "read the password from this file (mode 0600 or stricter) instead of the terminal")
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
}

func (s *secrets) pinFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.pinFile, "pin-file", "", "read the security key's PIN from this file (mode 0600 or stricter) instead of the terminal; unused by a key with a fingerprint")
}

// keyPIN returns the function the key asks for its PIN through, only when
// it has no built-in verification.
func (s *secrets) keyPIN(cmd *cobra.Command) func() (string, error) {
	return func() (string, error) {
		var b []byte
		var err error
		if s.pinFile != "" {
			b, err = readSecretFile(s.pinFile)
		} else {
			b, err = readTerminal(cmd, "Security key PIN: ")
		}
		pin := string(b)
		clear(b)
		return pin, err
	}
}

// fidoDevice is a FIDO2 factor that must be released.
type fidoDevice interface {
	theca.FIDO2
	Close() error
}

// openFIDO opens the attached security key; tests replace it.
var openFIDO = func(ctx context.Context, pin func() (string, error)) (fidoDevice, error) {
	return fido2.Open(ctx, pin)
}

func (s *secrets) password(cmd *cobra.Command, prompt string) ([]byte, error) {
	if s.passwordFile != "" {
		return readSecretFile(s.passwordFile)
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
		if dev != nil {
			dev.Close()
		}
	}
	if s.fido {
		var err error
		if dev, err = openFIDO(cmd.Context(), s.keyPIN(cmd)); err != nil {
			return u, wipe, err
		}
		u.FIDO = dev
		fmt.Fprintln(cmd.ErrOrStderr(), "Touch the security key when it blinks.")
	}
	if s.recoveryFile != "" {
		rc, err := readSecretFile(s.recoveryFile)
		if err != nil {
			return u, wipe, err
		}
		u.Recovery = string(rc)
		clear(rc)
	}
	if s.passwordFile != "" || s.recoveryFile == "" {
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
	if write {
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
	c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, theca.OpenOptions{})
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !c.Info().RollbackProtected {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: this container has no rollback counter: an older copy of it would be accepted")
	}
	return c, f, nil
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
	root.AddCommand(createCmd(), infoCmd(), verifyCmd(), exportCmd(), importCmd(), enrollKeyCmd(), serveCmd())
	return root
}

func createCmd() *cobra.Command {
	var s secrets
	var size, policy, fsKind string
	var journal uint32
	cmd := &cobra.Command{
		Use:   "create FILE",
		Short: "Create a new container; prints the recovery code once",
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
			pw, err := s.password(cmd, "New password: ")
			if err != nil {
				return err
			}
			defer clear(pw)
			if s.passwordFile == "" {
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
			f, err := os.OpenFile(args[0], os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			c, code, err := theca.Create(theca.FileBacking{File: f}, theca.CreateOptions{
				Sectors: n / theca.SectorSize, JournalEntries: journal, Hint: s.hint,
				Password: pw, Policy: pol,
			})
			if err == nil {
				if err = formatFS(c, fsKind); err != nil {
					c.Close()
				}
			}
			if err != nil {
				f.Close()
				os.Remove(args[0])
				return err
			}
			// The code is printed even if closing fails: the container is
			// formatted and the code is the only copy there will ever be.
			fmt.Fprintln(cmd.ErrOrStderr(), "Recovery code (shown once, never stored; write it down):")
			fmt.Fprintln(cmd.OutOrStdout(), code)
			fmt.Fprintln(cmd.ErrOrStderr(), "note: no rollback counter: an older copy of this container would be accepted")
			return closeBoth(c, f, nil)
		},
	}
	s.flags(cmd)
	cmd.Flags().StringVar(&size, "size", "", "logical size, a multiple of 4096 bytes (suffixes K, M, G, T)")
	cmd.Flags().StringVar(&policy, "policy", "any", "any: password or recovery code alone opens it; 2of3: both are needed")
	cmd.Flags().StringVar(&fsKind, "fs", "", "format the volume with this filesystem: exfat (serve needs one); empty: a raw volume")
	cmd.Flags().Uint32Var(&journal, "journal", 0, "journal entries (0: the default)")
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
			fmt.Fprintf(out, "rollback protected: %t\n", i.RollbackProtected)
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
			if s.passwordFile == "" && s.recoveryFile == "" {
				return errors.New("import reads the data from standard input: give --password-file or --recovery-file")
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
