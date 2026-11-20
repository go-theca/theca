//go:build darwin

package lockwatch

import (
	"context"
	"errors"
	"strings"
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

func TestDlopenFailures(t *testing.T) {
	saved := dlopen
	t.Cleanup(func() { dlopen = saved })
	for _, failing := range []string{"CoreGraphics", "CoreFoundation"} {
		want := errors.New("no " + failing)
		dlopen = func(path string, mode int) (uintptr, error) {
			if strings.Contains(path, failing) {
				return 0, want
			}
			return saved(path, mode)
		}
		if _, err := watch(context.Background()); !errors.Is(err, want) {
			t.Errorf("%s: %v", failing, err)
		}
	}
}

func TestLockedReading(t *testing.T) {
	released := 0
	mk := func(d, v uintptr, b bool) cf {
		return cf{
			sessionDict: func() uintptr { return d },
			dictGet:     func(_, _ uintptr) uintptr { return v },
			boolValue:   func(uintptr) bool { return b },
			release:     func(uintptr) { released++ },
		}
	}
	if mk(0, 1, true).locked() || released != 0 {
		t.Fatal("no dictionary must read unlocked and release nothing")
	}
	if mk(7, 0, true).locked() || released != 1 {
		t.Fatal("no key reads unlocked", released)
	}
	if mk(7, 1, false).locked() {
		t.Fatal("false flag read locked")
	}
	if !mk(7, 1, true).locked() || released != 3 {
		t.Fatal("true flag read unlocked", released)
	}
}
