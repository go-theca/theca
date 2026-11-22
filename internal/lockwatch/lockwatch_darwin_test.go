//go:build darwin

package lockwatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-macos/sessionwatch"
)

func TestReasonsMapsEvents(t *testing.T) {
	in := make(chan sessionwatch.Event, 3)
	in <- sessionwatch.Sleep
	in <- sessionwatch.Lock
	in <- sessionwatch.Session
	close(in)
	var got []string
	for r := range reasons(in) {
		got = append(got, r)
	}
	if strings.Join(got, ",") != "sleep,lock,session" {
		t.Fatalf("got %v", got)
	}
}

// watch routes the library's log through Logf and closes with the context. The
// test binary runs no main-thread run loop, so the library proves the observers
// undelivered and polls; it never sees a real lock.
func TestWatchRoutesLogAndCloses(t *testing.T) {
	saved := Logf
	t.Cleanup(func() { Logf = saved })
	var log []string
	Logf = func(format string, _ ...any) { log = append(log, format) }
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || !strings.Contains(log[0], "sessionwatch:") {
		t.Fatalf("log = %q", log)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("event on a quiet context")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed")
	}
}

func TestWatchError(t *testing.T) {
	saved := sessionWatch
	t.Cleanup(func() { sessionWatch = saved })
	boom := errors.New("boom")
	sessionWatch = func(context.Context) (<-chan sessionwatch.Event, error) { return nil, boom }
	if _, err := watch(context.Background()); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}
