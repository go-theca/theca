package lockwatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestReasonOf(t *testing.T) {
	for _, c := range []struct {
		msg  uint32
		w    uintptr
		want string
	}{
		{wmWTSSessionChange, wtsSessionLock, "lock"},
		{wmWTSSessionChange, wtsSessionLogoff, "shutdown"},
		{wmPowerBroadcast, pbtAPMSuspend, "sleep"},
		{wmWTSSessionChange, 1, ""},
		{wmPowerBroadcast, 18, ""},
		{wmClose, wtsSessionLock, ""},
	} {
		if got := reasonOf(c.msg, c.w); got != c.want {
			t.Errorf("reasonOf(%#x,%d) = %q, want %q", c.msg, c.w, got, c.want)
		}
	}
}

type fakeWindow struct {
	regErr  error
	pumpErr error
	handle  func(uint32, uintptr)
	stop    chan struct{}
	once    sync.Once

	mu        sync.Mutex
	destroyed bool
}

func (f *fakeWindow) Register() error { return f.regErr }
func (f *fakeWindow) Pump() error {
	if f.pumpErr != nil {
		return f.pumpErr
	}
	<-f.stop
	return nil
}
func (f *fakeWindow) Stop() { f.once.Do(func() { close(f.stop) }) }
func (f *fakeWindow) Destroy() {
	f.mu.Lock()
	f.destroyed = true
	f.mu.Unlock()
}

func TestWatchWindowDelivers(t *testing.T) {
	var fw *fakeWindow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := watchWindow(ctx, func(h func(uint32, uintptr)) (nativeWindow, error) {
		fw = &fakeWindow{handle: h, stop: make(chan struct{})}
		return fw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fw.handle(wmClose, 0) // ignored
	fw.handle(wmWTSSessionChange, wtsSessionLock)
	fw.handle(wmPowerBroadcast, pbtAPMSuspend) // dropped: one is waiting
	select {
	case r := <-ch:
		if r != "lock" {
			t.Errorf("reason = %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reason")
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("a second reason arrived")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed")
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if !fw.destroyed {
		t.Error("window not destroyed")
	}
}

func TestWatchWindowErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := watchWindow(context.Background(), func(func(uint32, uintptr)) (nativeWindow, error) {
		return nil, boom
	}); !errors.Is(err, boom) {
		t.Errorf("create error: %v", err)
	}
	var fw *fakeWindow
	if _, err := watchWindow(context.Background(), func(func(uint32, uintptr)) (nativeWindow, error) {
		fw = &fakeWindow{regErr: boom, stop: make(chan struct{})}
		return fw, nil
	}); !errors.Is(err, boom) {
		t.Errorf("register error: %v", err)
	}
}

func TestWatchWindowPumpEnds(t *testing.T) {
	ch, err := watchWindow(context.Background(), func(func(uint32, uintptr)) (nativeWindow, error) {
		return &fakeWindow{pumpErr: errors.New("loop"), stop: make(chan struct{})}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("reason from a dead loop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed after the loop ended")
	}
}
