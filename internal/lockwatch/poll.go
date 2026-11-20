package lockwatch

import (
	"context"
	"time"
)

// sleepGap is how far the wall clock may run ahead of the monotonic clock
// between two ticks before the difference counts as a sleep.
const sleepGap = 5 * time.Second

// pollInterval is how often the screen is looked at.
const pollInterval = 2 * time.Second

// delta returns the time since its previous call, read on the wall clock and on
// the monotonic one. On macOS the monotonic clock does not advance while the
// machine sleeps, so a wall-clock jump the monotonic clock did not make is a
// sleep.
type delta func() (wall, mono time.Duration)

func realDelta() delta {
	last := time.Now()
	return func() (time.Duration, time.Duration) {
		t := time.Now()
		w, m := t.Round(0).Sub(last.Round(0)), t.Sub(last)
		last = t
		return w, m
	}
}

// poll looks at the screen and the clocks on every tick, and reports the first
// reason the person has gone.
func poll(ctx context.Context, ticks <-chan time.Time, locked func() bool, d delta) <-chan string {
	out := make(chan string, 1)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticks:
			}
			w, m := d()
			switch {
			case w-m > sleepGap:
				out <- "sleep"
				return
			case locked():
				out <- "lock"
				return
			}
		}
	}()
	return out
}

// newPoll runs poll on a real ticker.
func newPoll(ctx context.Context, locked func() bool) <-chan string {
	t := time.NewTicker(pollInterval)
	ctx, cancel := context.WithCancel(ctx)
	out := poll(ctx, t.C, locked, realDelta())
	res := make(chan string, 1)
	go func() {
		defer close(res)
		defer cancel()
		defer t.Stop()
		if r, ok := <-out; ok {
			res <- r
		}
	}()
	return res
}
