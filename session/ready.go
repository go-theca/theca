package session

import (
	"strconv"
	"strings"
)

// ReadyEnv names the environment variable that carries, on Windows, the number
// of the inherited handle of the ready pipe: a process cannot be given "descriptor
// 3" there. The number is not a secret; the handle is valid only in the child.
const ReadyEnv = "THECA_READY_HANDLE"

// readyEnvEntry is the variable as an environment entry.
func readyEnvEntry(h uintptr) string { return ReadyEnv + "=" + strconv.FormatUint(uint64(h), 10) }

// parseReadyHandle reads the value of ReadyEnv; 0 or a malformed value is
// refused (a handle is a positive number).
func parseReadyHandle(v string) (uintptr, bool) {
	if v == "" || strings.TrimSpace(v) != v {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, strconv.IntSize)
	if err != nil || n == 0 {
		return 0, false
	}
	return uintptr(n), true
}
