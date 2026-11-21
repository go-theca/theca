package main

import (
	"fmt"
	"io"
)

// platformHarden is the seam tests replace: the in-process daemon tests must not
// deny a debugger to, nor remove the core file of, the test binary.
var platformHarden = hardenPlatform

// hardenProcess is the first thing the session daemon does (go-theca/theca#68):
// the daemon holds the unlocked container, and so its keys, for hours, and a
// crash must not write them to a core file nor a debugger read them. A refusal
// is reported on w and does not stop the daemon: the daemon can still work,
// only less protected, and a person is told which protection is missing.
//
// hardenPlatform is per operating system (harden_*.go); elsewhere it does
// nothing.
func hardenProcess(w io.Writer) {
	if err := platformHarden(); err != nil {
		fmt.Fprintf(w, "warning: the session process could not protect its memory (%v): a crash may leave the keys in a core file or a debugger may read them\n", err)
	}
}
