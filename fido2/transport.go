package fido2

import (
	"context"

	macfido "github.com/go-macos/fido"
)

// openTransport opens the attached key. go-macos/fido works on macOS and
// answers ErrUnsupported elsewhere; other systems get their transport later.
// On an error the returned key is a nil pointer inside the interface, which
// no caller reads: every caller checks the error first.
func openTransport(ctx context.Context) (key, error) { k, err := macfido.Open(ctx); return k, err }
