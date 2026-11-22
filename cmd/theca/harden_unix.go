//go:build linux || darwin

package main

import "github.com/go-authn/harden/memlock"

// disableDumps is replaced by tests.
var disableDumps = memlock.DisableDumps

// hardenPlatform removes the core file and refuses debuggers: RLIMIT_CORE 0 on
// both systems, PR_SET_DUMPABLE 0 on Linux, PT_DENY_ATTACH on macOS. Both calls
// are tried and their errors joined; go-authn/harden/memlock.DisableDumps does
// it (go-theca/theca#68).
func hardenPlatform() error { return disableDumps() }
