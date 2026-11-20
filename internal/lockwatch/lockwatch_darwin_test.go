//go:build darwin

package lockwatch

import (
	"context"
	"testing"
)

func TestWatchDarwin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range ch {
	}
}
