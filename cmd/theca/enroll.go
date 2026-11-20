package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-theca/theca"
)

// shellWord quotes a path for a command the person will paste.
func shellWord(w string) string {
	if w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:@%+=,") == "" {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}

// secretFlag is the flag that presented a secret, as the person would type it
// again, or a placeholder when it came from the terminal.
func secretFlag(name, file, from string) string {
	switch {
	case from != "":
		return "--" + name + "-from " + shellWord(from)
	case file != "":
		return "--" + name + "-file " + shellWord(file)
	}
	return "--" + name + "-file " + strings.ToUpper(name) + "_FILE"
}

// afterEnroll says what the pairing did NOT do, from the container itself: the
// password alone, and the recovery code alone, still open it when their slots
// are there. With --require it first removes the password-only slot, after a
// touch that PROVES the password with the key opens the container.
func afterEnroll(cmd *cobra.Command, c *theca.Container, dev fidoDevice, s *secrets, file string, partners []theca.Factor, require bool) error {
	var pw, rc *theca.Factor
	for i := range partners {
		switch partners[i].Kind {
		case "pw":
			pw = &partners[i]
		case "rc":
			rc = &partners[i]
		}
	}
	alone := func(f *theca.Factor) (bool, error) {
		if f == nil {
			return false, nil
		}
		idx, err := slotsOf(c, *f)
		return len(idx) > 0, err
	}
	pwAlone, err := alone(pw)
	if err != nil {
		return fmt.Errorf("the key is paired, but the slots that remain could not be checked: %w", err)
	}
	rcAlone, err := alone(rc)
	if err != nil {
		return fmt.Errorf("the key is paired, but the slots that remain could not be checked: %w", err)
	}
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
	pwFlag := secretFlag("password", s.passwordFile, s.passwordFrom)
	rcFlag := secretFlag("recovery", s.recoveryFile, s.recoveryFrom)
	device := ""
	if s.device != "" {
		device = " --device " + shellWord(s.device)
	}
	if require {
		if !pwAlone {
			fmt.Fprintln(out, "ok: the password alone did not open this container already: the key was required")
		} else {
			fmt.Fprintln(errw, "Touch the security key once more: the password with the key is checked before the password-only slot is removed.")
			pairs, err := theca.KeyPairs(cmd.Context(), dev, *pw)
			defer theca.WipeSets(pairs)
			if err == nil {
				var n int
				n, err = c.RemoveFactorSets([][]theca.Factor{{*pw}}, pairs)
				if err == nil {
					fmt.Fprintf(out, "ok: removed %d password-only slot(s): the container now needs the password together with the key\n", n)
				}
			}
			if err != nil {
				return fmt.Errorf("the key is paired, but --require did not complete and the password alone still opens the container: %w", err)
			}
			pwAlone = false
		}
	}
	if pwAlone {
		fmt.Fprintf(errw, "note: the password alone still opens this container: the key is an extra way in, not a requirement.\n"+
			"      To require it, run:\n"+
			"        theca slots remove %s --remove password --keep password+fido2 %s%s\n"+
			"      (or run enroll-key with --require).\n", shellWord(file), pwFlag, device)
	}
	switch {
	case rcAlone:
		fmt.Fprintf(errw, "note: the recovery code alone still opens this container. It is the way in if the key is lost; to make it need the key too, run:\n"+
			"        theca slots remove %s --remove recovery --keep password+fido2 %s %s%s\n", shellWord(file), pwFlag, rcFlag, device)
	case rc == nil:
		fmt.Fprintln(errw, "note: the recovery code was not presented, so it is not known whether it alone opens this container (under policy any it does).")
	}
	return nil
}
