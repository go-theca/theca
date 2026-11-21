package main

import (
	"context"
	"errors"
	"testing"
)

func TestOnMainThreadServesTheLoopWhileWorkRuns(t *testing.T) {
	saved := runMainLoop
	t.Cleanup(func() { runMainLoop = saved })
	boom := errors.New("boom")
	var ended bool
	runMainLoop = func(ctx context.Context) error {
		<-ctx.Done() // the loop lasts exactly as long as the work
		ended = true
		return errors.New("a loop that fails is not the work's error")
	}
	if err := onMainThread(func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("onMainThread = %v, want the work's error", err)
	}
	if !ended {
		t.Fatal("the loop was not stopped when the work ended")
	}
}

func TestServeMainLoopReturnsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Off the main thread (a test goroutine) darwin refuses and elsewhere it is a
	// no-op: either way it returns, and the caller ignores the answer.
	_ = serveMainLoop(ctx)
}
