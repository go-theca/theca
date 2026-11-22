//go:build windows

package session

import (
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// queryJob is replaced by tests.
var queryJob = windows.QueryInformationJobObject

// jobLimits are the limit flags of the job the process runs in (a nil job handle
// names the calling process's own job); the error says there is none, or that it
// cannot be read.
func jobLimits() (uint32, error) {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err := queryJob(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
	return info.BasicLimitInformation.LimitFlags, err
}

// inheritReady hands the child w as an inherited handle (os.Pipe makes
// non-inheritable ones, and ExtraFiles does not exist on Windows), names its
// number in ReadyEnv, and starts the child in a process group of its own, so
// that a Ctrl+C of the terminal that ran `theca open` does not reach it.
func inheritReady(child *exec.Cmd, w *os.File) error {
	h := windows.Handle(w.Fd())
	if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return err
	}
	child.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags:              windows.CREATE_NEW_PROCESS_GROUP | breakawayFlag(jobLimits()),
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(h)},
	}
	child.Env = append(os.Environ(), readyEnvEntry(uintptr(h)))
	return nil
}

// ReadyFile is the pipe the background process (`theca _serve`) tells its parent
// through: the handle ReadyEnv names, or nil when the process was not started by
// Start. The variable is removed so that no process below this one reads it.
func ReadyFile() *os.File {
	h, ok := parseReadyHandle(os.Getenv(ReadyEnv))
	os.Unsetenv(ReadyEnv)
	if !ok {
		return nil
	}
	return os.NewFile(h, "ready")
}
