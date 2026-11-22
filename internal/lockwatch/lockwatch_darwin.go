//go:build darwin

package lockwatch

import (
	"context"

	"github.com/go-macos/sessionwatch"
)

// sessionWatch is a seam the tests replace.
var sessionWatch = sessionwatch.Watch

// watch hands macOS to go-macos/sessionwatch (distributed lock notification,
// NSWorkspace sleep and session notifications, polling fallback). The
// notifications need the main thread's run loop (objc.RunMainLoop), which
// cmd/theca runs.
func watch(ctx context.Context) (<-chan string, error) {
	sessionwatch.Logf = Logf
	ch, err := sessionWatch(ctx)
	if err != nil {
		return nil, err
	}
	return reasons(ch), nil
}

// reasons turns sessionwatch's events into the strings theca's callers read.
func reasons(in <-chan sessionwatch.Event) <-chan string {
	out := make(chan string, 1)
	go func() {
		defer close(out)
		for ev := range in {
			out <- string(ev)
		}
	}()
	return out
}
