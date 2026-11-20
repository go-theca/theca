//go:build linux

package lockwatch

import (
	"context"
	"testing"
)

// watch needs a system bus; where there is none it says so. Either way the call
// returns, and a channel it returns closes with the context.
func TestWatchLinux(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := Watch(ctx)
	if err != nil {
		return
	}
	cancel()
	for range ch {
	}
}
