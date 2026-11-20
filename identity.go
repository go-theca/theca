package theca

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-theca/theca/internal/format"
)

// ErrCounterIdentity: the counter is not on the TPM the header pins (DESIGN
// 5.4.1), or cannot say which TPM it is on.
var ErrCounterIdentity = errors.New("theca: the rollback counter is not on the TPM this container is bound to")

// IdentifiedCounter is a Counter that can name the TPM it lives on: a digest
// of that TPM's endorsement key Name, IDSize bytes. A container made with one
// records the identity in its authenticated header and refuses, at every
// mount, a counter that reports another.
//
// The identity names a TPM, it does not prove the TPM answering is that one:
// whoever controls a software TPM, or the bus to a TPM, can report any
// identity (DESIGN 5.4.1).
type IdentifiedCounter interface {
	Counter
	Identity() ([]byte, error)
}

// IDSize is the size of a TPM identity.
const IDSize = format.IDSize

// ShortID renders an identity for a message: its first 6 bytes in hex.
func ShortID(id []byte) string {
	if len(id) > 6 {
		id = id[:6]
	}
	return hex.EncodeToString(id)
}

// identityOf asks ctr for its identity: nil when ctr cannot give one (a
// counter that is not an IdentifiedCounter).
func identityOf(ctr Counter) ([]byte, error) {
	ic, ok := ctr.(IdentifiedCounter)
	if !ok {
		return nil, nil
	}
	id, err := ic.Identity()
	if err != nil {
		return nil, fmt.Errorf("%w: reading the TPM identity: %v", ErrCounterIdentity, err)
	}
	if len(id) != IDSize {
		return nil, fmt.Errorf("%w: the TPM identity is %d bytes, want %d", ErrCounterIdentity, len(id), IDSize)
	}
	return id, nil
}

// checkIdentity refuses a counter whose TPM is not the pinned one. It runs
// before the counter is read: a value read from another TPM decides nothing.
func checkIdentity(ctr Counter, pinned []byte) error {
	if pinned == nil {
		return nil
	}
	got, err := identityOf(ctr)
	if err != nil {
		return err
	}
	if got == nil {
		return fmt.Errorf("%w: this counter cannot report its TPM identity (the container is bound to TPM %s)", ErrCounterIdentity, ShortID(pinned))
	}
	if !bytes.Equal(got, pinned) {
		return fmt.Errorf("%w: the counter is on TPM %s, the container is bound to TPM %s", ErrCounterIdentity, ShortID(got), ShortID(pinned))
	}
	return nil
}
