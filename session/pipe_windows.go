//go:build windows

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Seams the tests replace.
var (
	listenPipe = winio.ListenPipe
	dialPipe   = winio.DialPipeContext
	userSID    = currentUserSID
)

// currentUserSID is the string SID of the user this process runs as.
func currentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// SocketPath is where the session of profile name listens:
// \\.\pipe\theca-SID-NAME.
func SocketPath(name string) (string, error) {
	sid, err := userSID()
	if err != nil {
		return "", err
	}
	return PipePath(sid, name)
}

// listenEndpoint creates the pipe. The security descriptor names the user's SID
// alone; go-winio makes the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE
// (a pipe of that name that exists is an error, never shared) and refuses remote
// clients. A pipe another process answers on is ErrAlreadyOpen.
func listenEndpoint(path string) (net.Listener, error) {
	sid, err := userSID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := dialPipe(ctx, path); err == nil {
		c.Close()
		return nil, ErrAlreadyOpen
	}
	return listenPipe(path, &winio.PipeConfig{SecurityDescriptor: pipeSDDL(sid)})
}

func dialEndpoint(ctx context.Context, path string) (net.Conn, error) {
	return dialPipe(ctx, path)
}

// removeEndpoint: a pipe vanishes with its last handle.
func removeEndpoint(string) {}

// authorize admits the user's own processes: the pipe's DACL already refuses
// every other account, and the SID in the token of the client's process, which
// GetNamedPipeClientProcessId names, must be this process's own.
func authorize(c net.Conn) error {
	self, err := userSID()
	if err != nil {
		return err
	}
	return authorizeSID(c, self, clientSID)
}

// clientSID is the string SID of the process at the other end of a pipe.
func clientSID(pipe uintptr) (string, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe), &pid); err != nil {
		return "", fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return "", fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", errors.Join(errors.New("GetTokenUser"), err)
	}
	return u.User.Sid.String(), nil
}
