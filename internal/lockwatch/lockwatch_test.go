package lockwatch

import (
	"context"
	"strings"
	"testing"
	"time"
)

func recv(t *testing.T, ch <-chan string) (string, bool) {
	t.Helper()
	select {
	case s, ok := <-ch:
		return s, ok
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return "", false
	}
}

func TestLogTo(t *testing.T) {
	saved := Logf
	t.Cleanup(func() { Logf = saved })
	var b strings.Builder
	LogTo(&b)
	Logf("mode %d", 7)
	if got := b.String(); got != "mode 7\n" {
		t.Fatalf("got %q", got)
	}
}

func TestPoll(t *testing.T) {
	for _, tc := range []struct {
		name   string
		w, m   time.Duration
		locked bool
		want   string
	}{
		{"locked", time.Second, time.Second, true, "lock"},
		{"sleep", time.Hour, time.Second, false, "sleep"},
		{"sleep beats lock", time.Hour, time.Second, true, "sleep"},
	} {
		ticks := make(chan time.Time, 3)
		calls := 0
		d := func() (time.Duration, time.Duration) { return tc.w, tc.m }
		l := func() bool { calls++; return calls > 1 && tc.locked || false }
		ticks <- time.Time{}
		ticks <- time.Time{}
		got, ok := recv(t, poll(context.Background(), ticks, l, d))
		if tc.want == "sleep" {
			if !ok || got != "sleep" {
				t.Errorf("%s: %q %v", tc.name, got, ok)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("%s: %q %v", tc.name, got, ok)
		}
	}
}

func TestPollQuietThenCancel(t *testing.T) {
	ticks := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	out := poll(ctx, ticks, func() bool { return false }, func() (time.Duration, time.Duration) { return time.Second, time.Second })
	ticks <- time.Time{} // nothing to report
	cancel()
	if _, ok := recv(t, out); ok {
		t.Fatal("reported on a quiet screen")
	}
}

func TestRealDelta(t *testing.T) {
	d := realDelta()
	time.Sleep(10 * time.Millisecond)
	w, m := d()
	if w < 10*time.Millisecond || m < 10*time.Millisecond || w-m > sleepGap {
		t.Fatalf("wall %v mono %v", w, m)
	}
}

func TestNewPoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	out := newPoll(ctx, func() bool { return false })
	cancel()
	if _, ok := recv(t, out); ok {
		t.Fatal("reported on a quiet screen")
	}
	// A locked screen is seen on the first tick.
	out = newPoll(context.Background(), func() bool { return true })
	if r, ok := recv(t, out); !ok || r != "lock" {
		t.Fatal(r, ok)
	}
}
