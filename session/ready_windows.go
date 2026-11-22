//go:build windows

package session

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

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
		CreationFlags:              windows.CREATE_NEW_PROCESS_GROUP,
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
