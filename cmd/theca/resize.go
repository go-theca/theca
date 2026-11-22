package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-theca/theca"
	"github.com/spf13/cobra"
)

// journalCmd is `theca journal`, the commands about a container's journal.
func journalCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "journal",
		Short: "Change the journal of a container",
	}
	root.AddCommand(resizeCmd())
	return root
}

// shellQuote quotes a path for the swap commands printed for the user.
func shellQuote(p string) string {
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

func resizeCmd() *cobra.Command {
	var s secrets
	var out string
	var entries uint32
	cmd := &cobra.Command{
		Use:   "resize FILE --out NEW",
		Short: "Write a copy of a container with a journal of another size",
		Long: "Write NEW, a copy of FILE whose journal has the size asked for (--entries, by\n" +
			"default the size `theca create` would pick for this volume). The journal size\n" +
			"fixes the layout, so it cannot change in place: FILE is never rewritten.\n\n" +
			"NEW keeps every key slot, the policy, the counter binding and the content.\n" +
			"It is created exclusively (an existing NEW is refused), synced, then reopened,\n" +
			"verified sector by sector and compared with FILE by the hash of the volume;\n" +
			"nothing is reported before that succeeds.\n\n" +
			"FILE is opened like any mount, with the same factors and counter flags: that\n" +
			"mount is the only thing written to it. The command never swaps the files; it\n" +
			"prints the commands. Once NEW is mounted for real, the counter has moved past\n" +
			"FILE and FILE is refused as a rollback.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return errors.New("resize needs --out NEW")
			}
			if a, err := os.Stat(args[0]); err == nil {
				if b, err := os.Stat(out); err == nil && os.SameFile(a, b) {
					return errors.New("--out is FILE itself: a resize never rewrites its source")
				}
			}
			oo, wipeOpts, err := s.tpm.openOptions(cmd.Context())
			defer wipeOpts()
			if err != nil {
				return err
			}
			flag := os.O_RDONLY
			if oo.Counter != nil || oo.CounterFor != nil || oo.CounterDerived != nil {
				flag = os.O_RDWR
			}
			src, err := os.OpenFile(args[0], flag, 0)
			if err != nil {
				return err
			}
			defer src.Close()
			u, wipe, err := s.unlock(cmd)
			defer wipe()
			if err != nil {
				return err
			}
			dst, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			info, err := theca.Resize(cmd.Context(), theca.FileBacking{File: src}, u, oo, theca.FileBacking{File: dst}, theca.ResizeOptions{Entries: entries})
			// Resize synced the file: that is where a deferred write error shows,
			// and Close after a successful fsync has nothing left to report.
			dst.Close()
			if err = s.tpm.hint(err); err != nil {
				os.Remove(out)
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "ok: %s written, journal %d -> %d entries, %d sectors, %d bytes, volume sha256 %x verified through the copy\n",
				out, info.OldEntries, info.Entries, info.Sectors, info.Size, info.Hash)
			fmt.Fprintf(w, "FILE was not rewritten. To use the copy, run these yourself (nothing was swapped):\n")
			fmt.Fprintf(w, "  mv %s %s\n  mv %s %s\n", shellQuote(args[0]), shellQuote(args[0]+".old"), shellQuote(out), shellQuote(args[0]))
			fmt.Fprintf(w, "Mount the copy once before deleting %s: with a rollback counter, that mount moves the counter past it, and from then on the old file is refused.\n", args[0]+".old")
			return nil
		},
	}
	s.unlockFlags(cmd)
	cmd.Flags().StringVar(&out, "out", "", "the new container to write (must not exist)")
	cmd.Flags().Uint32Var(&entries, "entries", 0, "journal entries of the copy (0: the default for this volume)")
	return cmd
}
