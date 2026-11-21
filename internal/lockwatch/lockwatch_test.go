package lockwatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
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

func TestReason(t *testing.T) {
	v := func(b bool) []any { return []any{b} }
	props := func(iface string, m map[string]dbus.Variant) []any { return []any{iface, m, []string{}} }
	for _, tc := range []struct {
		s    dbus.Signal
		want string
	}{
		{dbus.Signal{Name: managerIf + ".PrepareForSleep", Body: v(true)}, "sleep"},
		{dbus.Signal{Name: managerIf + ".PrepareForSleep", Body: v(false)}, ""},
		{dbus.Signal{Name: managerIf + ".PrepareForSleep"}, ""},
		{dbus.Signal{Name: managerIf + ".PrepareForShutdown", Body: v(true)}, "shutdown"},
		{dbus.Signal{Name: managerIf + ".PrepareForShutdown", Body: v(false)}, ""},
		{dbus.Signal{Name: sessionIf + ".Lock"}, "lock"},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props(sessionIf, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)})}, "lock"},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props(sessionIf, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(false)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props(sessionIf, map[string]dbus.Variant{"Other": dbus.MakeVariant(true)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props("other.Iface", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: []any{sessionIf, "not a map"}}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged"}, ""},
		{dbus.Signal{Name: "x.Y"}, ""},
	} {
		if got := reason(&tc.s); got != tc.want {
			t.Errorf("%s %v: %q want %q", tc.s.Name, tc.s.Body, got, tc.want)
		}
	}
}

type fakeBus struct {
	ch       chan<- *dbus.Signal
	matchErr error
	matches  int
	removed  bool
	closed   bool
}

func (b *fakeBus) AddMatchSignalContext(_ context.Context, _ ...dbus.MatchOption) error {
	b.matches++
	return b.matchErr
}
func (b *fakeBus) Signal(ch chan<- *dbus.Signal)    { b.ch = ch }
func (b *fakeBus) RemoveSignal(chan<- *dbus.Signal) { b.removed = true }
func (b *fakeBus) Close() error                     { b.closed = true; return nil }

func TestWatchBus(t *testing.T) {
	b := &fakeBus{}
	out, err := watchBus(context.Background(), func() (busConn, error) { return b, nil })
	if err != nil || b.matches != len(matches) {
		t.Fatal(err, b.matches)
	}
	b.ch <- &dbus.Signal{Name: "irrelevant.Signal"}
	b.ch <- &dbus.Signal{Name: sessionIf + ".Lock"}
	if r, ok := recv(t, out); !ok || r != "lock" {
		t.Fatal(r, ok)
	}
	if _, ok := recv(t, out); ok {
		t.Fatal("channel not closed")
	}
	if !b.removed || !b.closed {
		t.Fatal("connection not released")
	}
}

func TestWatchBusEnds(t *testing.T) {
	b := &fakeBus{}
	ctx, cancel := context.WithCancel(context.Background())
	out, _ := watchBus(ctx, func() (busConn, error) { return b, nil })
	cancel()
	if _, ok := recv(t, out); ok {
		t.Fatal("reported after cancel")
	}
	// The bus closing its signal channel ends the watch too.
	b2 := &fakeBus{}
	out, _ = watchBus(context.Background(), func() (busConn, error) { return b2, nil })
	close(b2.ch)
	if _, ok := recv(t, out); ok {
		t.Fatal("reported on a closed bus")
	}
}

func TestWatchBusErrors(t *testing.T) {
	boom := errors.New("no bus")
	if _, err := watchBus(context.Background(), func() (busConn, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	b := &fakeBus{matchErr: boom}
	if _, err := watchBus(context.Background(), func() (busConn, error) { return b, nil }); !errors.Is(err, boom) || !b.removed || !b.closed {
		t.Fatal(err, b)
	}
}

func TestAsBus(t *testing.T) {
	boom := errors.New("x")
	if c, err := asBus(nil, boom); c != nil || !errors.Is(err, boom) {
		t.Fatal(c, err)
	}
	if c, err := asBus(&dbus.Conn{}, nil); c == nil || err != nil {
		t.Fatal(c, err)
	}
}
