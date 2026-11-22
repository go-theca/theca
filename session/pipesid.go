package session

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// The Windows channel, minus the Win32 calls: the name of the pipe, its
// security descriptor and the decision about a client. They are plain Go so that
// every system tests them; pipe_windows.go supplies the calls.

// maxPipeName is the limit of a pipe name, without the \\.\pipe\ prefix
// (CreateNamedPipe: 256 characters).
const maxPipeName = 256

// validSID reports whether s looks like a string SID (S-1-5-21-...): it ends up
// inside a security descriptor string and a pipe name, so nothing else may
// pass.
func validSID(s string) bool {
	if len(s) < 5 || !strings.HasPrefix(s, "S-") {
		return false
	}
	for _, r := range s {
		if r != '-' && r != 'S' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// PipePath is where the session of profile name, of the user whose SID is sid,
// listens: \\.\pipe\theca-SID-NAME.
func PipePath(sid, name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	if !validSID(sid) {
		return "", fmt.Errorf("session: bad user SID %q", clip(sid, 32))
	}
	n := "theca-" + sid + "-" + name
	if len(n) > maxPipeName {
		return "", fmt.Errorf("session: pipe name for %q is longer than %d characters", clip(name, 32), maxPipeName)
	}
	return `\\.\pipe\` + n, nil
}

// pipeSDDL is the security descriptor of the pipe: a protected DACL (nothing is
// inherited) with one entry, all access for the user's SID. LocalSystem and the
// administrators are not named: they can take ownership anyway, and a pipe that
// grants them nothing is one fewer thing to reason about.
func pipeSDDL(sid string) string { return "D:P(A;;GA;;;" + sid + ")" }

// handleConn is what a connection from a pipe offers: the handle of the pipe.
type handleConn interface {
	net.Conn
	Fd() uintptr
}

// authorizeSID admits the client whose process runs under the SID self. A
// connection that is not a pipe, or whose process cannot be identified, is
// refused.
func authorizeSID(c net.Conn, self string, clientSID func(pipe uintptr) (string, error)) error {
	h, ok := c.(handleConn)
	if !ok {
		return errors.New("session: not a named pipe")
	}
	sid, err := clientSID(h.Fd())
	if err != nil || sid != self {
		return ErrPeer
	}
	return nil
}
