//go:build unix

package session

import (
	"net"
	"os"
)

// chmod is replaced by tests.
var chmod = os.Chmod

// listenUnix listens at path and makes the socket owner-only. The directory
// is already mode 0700, so no one else can reach it in between.
func listenUnix(path string) (net.Listener, error) {
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
