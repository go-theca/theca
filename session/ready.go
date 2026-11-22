package session

import "strconv"

// ReadyEnv names the environment variable that carries, on Windows, the number
// of the inherited handle of the ready pipe: a process cannot be given "descriptor
// 3" there. The number is not a secret; the handle is valid only in the child.
const ReadyEnv = "THECA_READY_HANDLE"

// readyEnvEntry is the variable as an environment entry.
func readyEnvEntry(h uintptr) string { return ReadyEnv + "=" + strconv.FormatUint(uint64(h), 10) }

// Process creation and job limit flags (winbase.h, winnt.h).
const (
	createBreakawayFromJob  = 0x01000000
	jobLimitBreakawayOK     = 0x00000800
	jobLimitSilentBreakaway = 0x00001000
)

// breakawayFlag is CREATE_BREAKAWAY_FROM_JOB when the job this process runs in
// (limits, or err when the query failed: no job, or no way to tell) lets a child
// leave it, and 0 otherwise. A service manager or sshd puts a session in a job that
// ends every process in it when the session ends; the background process of `theca
// open` must outlive the terminal that started it. Asking for the breakaway where
// the job does not allow it makes CreateProcess fail, so it is asked only where the
// job says it is allowed; a job with silent breakaway needs no flag.
func breakawayFlag(limits uint32, err error) uint32 {
	if err != nil || limits&jobLimitBreakawayOK == 0 || limits&jobLimitSilentBreakaway != 0 {
		return 0
	}
	return createBreakawayFromJob
}

// parseReadyHandle reads the value of ReadyEnv; 0 or a malformed value is
// refused (a handle is a positive number).
func parseReadyHandle(v string) (uintptr, bool) {
	n, err := strconv.ParseUint(v, 10, strconv.IntSize)
	if err != nil || n == 0 {
		return 0, false
	}
	return uintptr(n), true
}
