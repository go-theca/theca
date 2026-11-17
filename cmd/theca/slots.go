package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
	"github.com/go-theca/theca/internal/format"
)

// factorSets are what --remove and --keep name.
var factorSets = map[string][]string{
	"password":          {"pw"},
	"recovery":          {"rc"},
	"password+recovery": {"pw", "rc"},
}

// slotsOf is the library call, replaceable by tests: an I/O failure while
// trial-opening the slots cannot be provoked through the command.
var slotsOf = (*theca.Container).SlotsOf

// presented holds the factors derived from the secrets the user gave, by kind.
type presented map[string]theca.Factor

func (p presented) wipe() {
	for _, f := range p {
		f.Zeroize()
	}
}

// set resolves a --remove/--keep value to factors that were presented.
func (p presented) set(flag, value string) ([]theca.Factor, error) {
	kinds, ok := factorSets[value]
	if !ok {
		return nil, fmt.Errorf("--%s %q: want password, recovery or password+recovery", flag, value)
	}
	var out []theca.Factor
	for _, k := range kinds {
		f, ok := p[k]
		if !ok {
			name, file := "password", "--password-file"
			if k == "rc" {
				name, file = "recovery code", "--recovery-file"
			}
			return nil, fmt.Errorf("--%s %s needs the %s: give %s", flag, value, name, file)
		}
		out = append(out, f)
	}
	return out, nil
}

// openWithFactors unlocks path read-write and derives the password and
// recovery factors from the same secrets, so a command can name factor sets.
func openWithFactors(cmd *cobra.Command, path string, s *secrets) (*theca.Container, *os.File, presented, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*theca.Container, *os.File, presented, error) {
		f.Close()
		return nil, nil, nil, err
	}
	salt := make([]byte, format.SaltSize)
	if _, err := f.ReadAt(salt, 0); err != nil {
		return fail(err)
	}
	u, wipe, err := s.unlock(cmd)
	defer wipe()
	if err != nil {
		return fail(err)
	}
	p := presented{}
	if len(u.Password) > 0 {
		pw, err := theca.PasswordFactor(s.hint, u.Password, salt)
		if err != nil {
			return fail(err)
		}
		p["pw"] = pw
	}
	if u.Recovery != "" {
		rc, err := theca.RecoveryFactor(u.Recovery)
		if err != nil {
			p.wipe()
			return fail(err)
		}
		p["rc"] = rc
	}
	c, err := theca.Open(cmd.Context(), theca.FileBacking{File: f}, u, theca.OpenOptions{})
	if err != nil {
		p.wipe()
		return fail(err)
	}
	if !c.Info().RollbackProtected {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: this container has no rollback counter: an older copy of it would be accepted")
	}
	return c, f, p, nil
}

func slotsCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "slots",
		Short: "List or remove the keyslots of a container",
		Long: "A keyslot holds nothing that says what opens it, so `list` can only say which\n" +
			"slots the factors you present open. Secrets come from --password-file and\n" +
			"--recovery-file, or the terminal.",
	}
	root.AddCommand(slotsListCmd(), slotsRemoveCmd())
	return root
}

func slotsListCmd() *cobra.Command {
	var s secrets
	cmd := &cobra.Command{
		Use:   "list FILE",
		Short: "Show the recorded slots and which ones the presented factors open",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, f, p, err := openWithFactors(cmd, args[0], &s)
			if err != nil {
				return err
			}
			defer p.wipe()
			out := cmd.OutOrStdout()
			rec := c.Slots()
			fmt.Fprintf(out, "recorded slots: %s (%d of %d)\n", joinInts(rec), len(rec), format.NumSlots)
			for _, name := range []string{"password", "recovery", "password+recovery"} {
				fs, err := p.set("list", name)
				if err != nil {
					continue // not presented
				}
				idx, err := slotsOf(c, fs...)
				if err != nil {
					return closeBoth(c, f, err)
				}
				fmt.Fprintf(out, "opened by the %s: %s\n", name, joinInts(idx))
			}
			return closeBoth(c, f, nil)
		},
	}
	s.flags(cmd)
	s.recoveryFlag(cmd)
	return cmd
}

func slotsRemoveCmd() *cobra.Command {
	var s secrets
	var remove, keep string
	cmd := &cobra.Command{
		Use:   "remove FILE --remove SET --keep SET",
		Short: "Remove the slot a factor set opens, keeping a different way in",
		Long: "Remove the slot(s) that SET opens (password, recovery or password+recovery).\n" +
			"--keep names a DIFFERENT set that must still open the container afterwards:\n" +
			"it is checked before anything is written, and a removal that would leave\n" +
			"no way in is refused. Both sets are presented with --password-file and\n" +
			"--recovery-file.\n\n" +
			"This only stops access to this copy: anyone holding an older copy of the\n" +
			"container can still open it with the removed factor.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if remove == "" || keep == "" {
				return errors.New("give --remove and --keep (password, recovery or password+recovery)")
			}
			c, f, p, err := openWithFactors(cmd, args[0], &s)
			if err != nil {
				return err
			}
			defer p.wipe()
			rm, err := p.set("remove", remove)
			if err != nil {
				return closeBoth(c, f, err)
			}
			kp, err := p.set("keep", keep)
			if err != nil {
				return closeBoth(c, f, err)
			}
			n, err := c.RemoveFactors(rm, kp)
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: removed %d slot(s) opened by the %s; the %s still opens it\n", n, remove, keep)
				fmt.Fprintln(cmd.ErrOrStderr(), "note: a copy of the container made before now still opens with the removed factor")
			}
			return closeBoth(c, f, err)
		},
	}
	s.flags(cmd)
	s.recoveryFlag(cmd)
	cmd.Flags().StringVar(&remove, "remove", "", "the factor set whose slot to remove: password, recovery or password+recovery")
	cmd.Flags().StringVar(&keep, "keep", "", "a different factor set that must still open the container")
	return cmd
}

func joinInts(v []int) string {
	if len(v) == 0 {
		return "none"
	}
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}
