package session

import (
	"errors"
	"net"
)

// getPeerUID asks the kernel for the user ID of the process at the other end of
// the socket fd (peer_linux.go, peer_darwin.go); tests replace it.
var getPeerUID = getPeerUIDOS

// peerUIDOf is the user ID of the process at the other end of c.
func peerUIDOf(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("session: not a Unix socket")
	}
	raw, _ := uc.SyscallConn() // fails only on a nil conn, which the type check above excludes
	uid := -1
	var gerr error
	if err := raw.Control(func(fd uintptr) { uid, gerr = getPeerUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, gerr
}
