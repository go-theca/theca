//go:build unix

package session

import (
	"os"
	"os/exec"
)

// inheritReady gives the child w as descriptor 3.
func inheritReady(child *exec.Cmd, w *os.File) error {
	child.ExtraFiles = []*os.File{w}
	return nil
}

// ReadyFile is the pipe the background process (`theca _serve`) tells its parent
// through: descriptor 3, or nil when the process was not started by Start.
func ReadyFile() *os.File { return os.NewFile(3, "ready") }
