package fido2

import (
	"context"
	"fmt"

	linuxfido "github.com/go-gnulinux/fido"
	macfido "github.com/go-macos/fido"
)

// openTransport opens the attached key over the operating system's CTAPHID
// transport, chosen by GOOS (Windows takes another route, see platform.go):
//
//   - macOS: go-macos/fido (IOKit HID).
//   - Linux: go-gnulinux/fido (/dev/hidraw*, found by the FIDO usage page
//     0xF1D0 in the report descriptor). The node is root-only on a stock
//     system: a udev rule granting the user access (libfido2's 70-u2f.rules)
//     is needed, and the error says so when a key is found but not openable.
//
// On an error the returned key is a nil pointer inside the interface, which no
// caller reads: every caller checks the error first.
func openTransport(ctx context.Context) (key, error) {
	switch goos {
	case "darwin":
		k, err := macfido.Open(ctx)
		return k, err
	case "linux":
		k, err := linuxfido.Open(ctx)
		return k, err
	}
	return nil, fmt.Errorf("fido2: no CTAP transport for %s", goos)
}
