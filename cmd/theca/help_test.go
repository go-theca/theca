package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestFlagValueNamesAreOneWord: pflag takes the first `backquoted` text of a
// usage string as the flag's value name, so "(`fido list` prints them)"
// printed "--device fido list" in the help. Every flag of every command must
// show a one-word value name (or none).
func TestFlagValueNamesAreOneWord(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		check := func(f *pflag.Flag) {
			name, _ := pflag.UnquoteUsage(f)
			if strings.ContainsAny(name, " \t") {
				t.Errorf("%s --%s: value name %q is not one word", c.CommandPath(), f.Name, name)
			}
		}
		c.LocalFlags().VisitAll(check)
		c.PersistentFlags().VisitAll(check)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(RootCmd())
}

// TestDeviceFlagHelp pins the rendered help line of --device.
func TestDeviceFlagHelp(t *testing.T) {
	r := run(nil, "enroll-key", "--help")
	if r.e != nil {
		t.Fatal(r.e)
	}
	if !strings.Contains(r.out, "--device ID ") {
		t.Errorf("help does not show \"--device ID\":\n%s", r.out)
	}
}
