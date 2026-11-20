//go:build !linux && !darwin

package lockwatch

import (
	"context"
	"errors"
	"testing"
)

func TestWatchOther(t *testing.T) {
	if _, err := Watch(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}
