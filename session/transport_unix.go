//go:build unix

package session

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Seams the tests replace.
var (
	runtimeDir    = func() string { return os.Getenv("XDG_RUNTIME_DIR") }
	userConfigDir = os.UserConfigDir
)

// maxSocketPath is the shortest sun_path limit among the systems served
// (macOS: 104, with the terminating NUL).
const maxSocketPath = 103

// SocketPath is where the session of profile name listens:
// $XDG_RUNTIME_DIR/theca/NAME.sock, else os.UserConfigDir()/theca/run/NAME.sock.
func SocketPath(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	var dir string
	if r := runtimeDir(); r != "" {
		dir = filepath.Join(r, "theca")
	} else {
		c, err := userConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(c, "theca", "run")
	}
	p := filepath.Join(dir, name+".sock")
	if len(p) > maxSocketPath {
		return "", fmt.Errorf("session: socket path %s is longer than %d bytes (set XDG_RUNTIME_DIR to a shorter directory)", p, maxSocketPath)
	}
	return p, nil
}

// peerUID returns the user ID on the other end of c; replaced by tests, and
// by platform files. It lives in peer_*.go.
var peerUID = peerUIDOf

var getuid = os.Getuid

// authorize admits the owner of the session and no one else.
func authorize(c net.Conn) error {
	uid, err := peerUID(c)
	if err != nil || uid != getuid() {
		return ErrPeer
	}
	return nil
}

// listenEndpoint creates the socket. A socket another process answers on is
// ErrAlreadyOpen; one nobody answers on is a leftover and is replaced.
func listenEndpoint(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, ErrAlreadyOpen
	}
	os.Remove(path) // a leftover, or nothing
	return listenUnix(path)
}

func dialEndpoint(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// removeEndpoint deletes the socket file.
func removeEndpoint(path string) { os.Remove(path) }
