//go:build unix && !linux && !darwin

package session

import "errors"

// No peer credentials here: every client is refused, so no session is served.
func getPeerUIDOS(int) (int, error) {
	return -1, errors.New("session: peer credentials are not available on this system")
}
