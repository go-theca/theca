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

// factorSet is what --remove and --keep name: the factors that together open
// a slot. kinds are the password ("pw") and recovery code ("rc") in it; key is
// set when the FIDO2 key is part of it, in which case there is exactly one
// kind, the partner the key pairs with (DESIGN 19, I21).
type factorSet struct {
	kinds []string
	key   bool
}

const setWant = "password, recovery, password+recovery, password+fido2 or recovery+fido2"

// parseSet reads a SET: one or more of password, recovery and fido2 joined by
// "+", in any order, none twice. A key opens a slot only with ONE partner, so
// fido2 alone and password+recovery+fido2 are not sets.
func parseSet(flag, value string) (factorSet, error) {
	var pw, rc, key bool
	for _, tok := range strings.Split(value, "+") {
		var seen *bool
		switch tok {
		case "password":
			seen = &pw
		case "recovery":
			seen = &rc
		case "fido2":
			seen = &key
		default:
			return factorSet{}, fmt.Errorf("--%s %q: want %s", flag, value, setWant)
		}
		if *seen {
			return factorSet{}, fmt.Errorf("--%s %q: %s twice; want %s", flag, value, tok, setWant)
		}
		*seen = true
	}
	var fs factorSet
	if pw {
		fs.kinds = append(fs.kinds, "pw")
	}
	if rc {
		fs.kinds = append(fs.kinds, "rc")
	}
	fs.key = key
	if len(fs.kinds) == 0 || key && len(fs.kinds) != 1 {
		return factorSet{}, fmt.Errorf("--%s %q: a key opens a slot only together with the password or the recovery code, not both; want %s", flag, value, setWant)
	}
	return fs, nil
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

// factors are the presented password and recovery code a set names.
func (p presented) factors(flag, value string, fs factorSet) ([]theca.Factor, error) {
	var out []theca.Factor
	for _, k := range fs.kinds {
		f, ok := p[k]
		if !ok {
			name, file := "password", "--password-from REF"
			if k == "rc" {
				name, file = "recovery code", "--recovery-from REF"
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
	c, err := s.openContainer(cmd, f, u)
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
			"slots the factors you present open. Secrets come from --password-from and\n" +
			"--recovery-from, or the terminal.",
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
				set, _ := parseSet("list", name) // the three that need no key
				fs, err := p.factors("list", name, set)
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
	s.unlockFlags(cmd)
	return cmd
}

func slotsRemoveCmd() *cobra.Command {
	var s secrets
	var remove, keep string
	cmd := &cobra.Command{
		Use:   "remove FILE --remove SET --keep SET",
		Short: "Remove the slot a factor set opens, keeping a different way in",
		Long: "Remove the slot(s) that SET opens: password, recovery, password+recovery,\n" +
			"password+fido2 or recovery+fido2 (the key paired with that factor).\n" +
			"--keep names a DIFFERENT set that must still open the container afterwards:\n" +
			"it is checked before anything is written, and a removal that would leave\n" +
			"no way in is refused. Sets are presented with --password-from and\n" +
			"--recovery-from. A set with fido2 touches the key ONCE (--device NAME\n" +
			"chooses it, --pin-from its PIN); the slot it opens must exist and must not\n" +
			"be among the removed ones. A container the key alone opens needs --fido2\n" +
			"as well, to be opened at all: that is a second touch.\n\n" +
			"To make the key mandatory: --remove password --keep password+fido2.\n\n" +
			"This only stops access to this copy: anyone holding an older copy of the\n" +
			"container can still open it with the removed factor.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if remove == "" || keep == "" {
				return errors.New("give --remove and --keep (" + setWant + ")")
			}
			rmSet, err := parseSet("remove", remove)
			if err != nil {
				return err
			}
			kpSet, err := parseSet("keep", keep)
			if err != nil {
				return err
			}
			c, f, p, err := openWithFactors(cmd, args[0], &s)
			if err != nil {
				return err
			}
			defer p.wipe()
			rm, kp, pairs, err := p.resolve(cmd, &s, remove, rmSet, keep, kpSet)
			defer theca.WipeSets(pairs)
			if err != nil {
				return closeBoth(c, f, err)
			}
			n, err := c.RemoveFactorSets(rm, kp)
			if errors.Is(err, theca.ErrLastWay) && kpSet.key {
				err = fmt.Errorf("%w (does the key you touched hold a credential enrolled in THIS container, paired with that factor?)", err)
			}
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "ok: removed %d slot(s) opened by the %s; the %s still opens it\n", n, remove, keep)
				fmt.Fprintln(cmd.ErrOrStderr(), "note: a copy of the container made before now still opens with the removed factor")
			}
			return closeBoth(c, f, err)
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().StringVar(&remove, "remove", "", "the factor set whose slot to remove: "+setWant)
	cmd.Flags().StringVar(&keep, "keep", "", "a different factor set that must still open the container: "+setWant)
	return cmd
}

// resolve turns --remove and --keep into the factor sets RemoveFactorSets
// takes. A set with the key is checked here, before anything is written: the
// key is touched ONCE (KeyPairs), and the slots its pairs open are what the set
// names. It returns the pairs so the caller wipes them.
func (p presented) resolve(cmd *cobra.Command, s *secrets, remove string, rmSet factorSet, keep string, kpSet factorSet) (rm, kp, pairs [][]theca.Factor, err error) {
	rmBase, err := p.factors("remove", remove, rmSet)
	if err != nil {
		return nil, nil, nil, err
	}
	kpBase, err := p.factors("keep", keep, kpSet)
	if err != nil {
		return nil, nil, nil, err
	}
	if rmSet.key || kpSet.key {
		// One touch serves every partner a set names.
		var partners []theca.Factor
		for _, k := range []string{"pw", "rc"} {
			if rmSet.key && rmSet.kinds[0] == k || kpSet.key && kpSet.kinds[0] == k {
				partners = append(partners, p[k])
			}
		}
		dev, err := openFIDO(cmd.Context(), s.keyPIN(cmd), s.device)
		if err != nil {
			return nil, nil, nil, err
		}
		defer dev.Close()
		fmt.Fprintln(cmd.ErrOrStderr(), "Touch the security key once: the set with the key is checked before anything is written.")
		pairs, err = theca.KeyPairs(cmd.Context(), dev, partners...)
		if errors.Is(err, theca.ErrNoCredential) {
			err = fmt.Errorf("%w: the key holds no Theca credential, so it cannot be part of a set (enroll it with enroll-key)", err)
		}
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return withPairs(rmSet, rmBase, pairs), withPairs(kpSet, kpBase, pairs), pairs, nil
}

// withPairs is the sets a --remove/--keep value stands for: the one set of its
// factors, or, with the key, one set per Theca credential the key holds paired
// with that partner.
func withPairs(fs factorSet, base []theca.Factor, pairs [][]theca.Factor) [][]theca.Factor {
	if !fs.key {
		return [][]theca.Factor{base}
	}
	var out [][]theca.Factor
	for _, pr := range pairs {
		if pr[0].Kind == fs.kinds[0] {
			out = append(out, pr)
		}
	}
	return out
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
