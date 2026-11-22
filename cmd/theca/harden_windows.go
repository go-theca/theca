//go:build windows

package main

import "golang.org/x/sys/windows"

// setErrorMode is replaced by tests.
var setErrorMode = windows.SetErrorMode

// hardenPlatform asks the system not to show the Windows Error Reporting box nor
// the critical-error and open-file boxes (SetErrorMode: SEM_FAILCRITICALERRORS |
// SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX), so that a crash ends the process
// without handing the person a report to send.
//
// Windows has no call that makes a process undumpable (no PR_SET_DUMPABLE, no
// PT_DENY_ATTACH, no RLIMIT_CORE): a debugger of the same user, and an
// administrator, can read the process, and a dump taken by WER's LocalDumps
// setting (HKLM, an administrator's choice) is not stopped by SetErrorMode. What
// remains is the memory discipline of the key material itself (wiped on close,
// never written by this program).
func hardenPlatform() error {
	setErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX | windows.SEM_NOOPENFILEERRORBOX)
	return nil
}
