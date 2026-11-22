package pin

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/go-authn/harden/memlock"
)

// fake counts the calls; with page size 1 every byte is its own page, so a
// range of n bytes makes n calls and the refusals can be placed exactly.
type fake struct {
	locks, unlocks int
	refuse         error
	refuseAt       int // 1-based call that is refused; 0: every call when refuse != nil
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{}
	restore := SetLocker(memlock.NewLocker(memlock.Syscalls{
		Lock: func(unsafe.Pointer, uintptr) error {
			f.locks++
			if f.refuse != nil && (f.refuseAt == 0 || f.refuseAt == f.locks) {
				return f.refuse
			}
			return nil
		},
		Unlock: func(unsafe.Pointer, uintptr) { f.unlocks++ },
	}, 1))
	t.Cleanup(func() {
		restore()
		SetMode(BestEffort)
		SetReporter(nil)
	})
	SetMode(BestEffort)
	SetReporter(nil)
	return f
}

func TestOffAndEmptyDoNothing(t *testing.T) {
	f := newFake(t)
	b := make([]byte, 8)
	SetMode(Off)
	if r, err := Lock(unsafe.Pointer(&b[0]), 8); r != nil || err != nil || f.locks != 0 {
		t.Fatalf("Off: %v %v %d", r, err, f.locks)
	}
	SetMode(BestEffort)
	if r, err := Lock(unsafe.Pointer(&b[0]), 0); r != nil || err != nil || f.locks != 0 {
		t.Fatalf("empty: %v %v %d", r, err, f.locks)
	}
}

func TestABestEffortRefusalIsReportedOnceAndTheRestStillLocks(t *testing.T) {
	f := newFake(t)
	f.refuse, f.refuseAt = errors.New("cannot allocate memory"), 1
	var heard []error
	SetReporter(func(err error) { heard = append(heard, err) })
	b := make([]byte, 3)
	r, err := Lock(unsafe.Pointer(&b[0]), 3)
	if err != nil || r == nil {
		t.Fatalf("best effort returned %v %v", r, err)
	}
	f.refuseAt = 0
	if _, err := Lock(unsafe.Pointer(&b[0]), 1); err != nil { // refused again: not reported twice
		t.Fatal(err)
	}
	if len(heard) != 1 || !strings.Contains(heard[0].Error(), "cannot allocate memory") {
		t.Fatalf("heard %v, want one report", heard)
	}
	if Failed() != nil {
		t.Fatal("Failed reports in best-effort mode")
	}
	r.Release()
	if f.unlocks != 2 { // the two pages that were not refused
		t.Fatalf("%d unlocks, want 2", f.unlocks)
	}
}

func TestAnUnsupportedPlatformIsNotReported(t *testing.T) {
	f := newFake(t)
	f.refuse = &memlock.UnsupportedError{Op: "lock memory"}
	SetReporter(func(err error) { t.Errorf("reported %v", err) })
	b := make([]byte, 2)
	if r, err := Lock(unsafe.Pointer(&b[0]), 2); err != nil || r == nil {
		t.Fatalf("%v %v", r, err)
	}
}

func TestARefusalWithNoReporterIsSilent(t *testing.T) {
	f := newFake(t)
	f.refuse = errors.New("no")
	b := make([]byte, 2)
	if _, err := Lock(unsafe.Pointer(&b[0]), 2); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredTurnsARefusalIntoAnErrorAndHoldsNothing(t *testing.T) {
	f := newFake(t)
	SetMode(Required)
	f.refuse, f.refuseAt = errors.New("operation not permitted"), 3
	b := make([]byte, 3)
	r, err := Lock(unsafe.Pointer(&b[0]), 3)
	if err == nil || r != nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("Required: %v %v", r, err)
	}
	if f.unlocks != 2 {
		t.Fatalf("the two pages locked before the refusal were not given back: %d unlocks", f.unlocks)
	}
	first := Failed()
	if first == nil {
		t.Fatal("Failed is nil after a refusal")
	}
	f.refuseAt = 0
	Lock(unsafe.Pointer(&b[0]), 1)
	if Failed() != first {
		t.Fatal("Failed changed: it is the FIRST refusal")
	}
	SetMode(Required)
	if Failed() != nil {
		t.Fatal("SetMode did not forget the refusal")
	}
	if Current() != Required {
		t.Fatal("Current")
	}
}

func TestRequiredReturnsTheRegionWhenNothingIsRefused(t *testing.T) {
	f := newFake(t)
	SetMode(Required)
	b := make([]byte, 2)
	r, err := Lock(unsafe.Pointer(&b[0]), 2)
	if err != nil || r == nil || f.locks != 2 || Failed() != nil {
		t.Fatalf("%v %v %d", r, err, f.locks)
	}
	r.Release()
}

func TestModeNamesRoundTrip(t *testing.T) {
	for _, m := range []Mode{BestEffort, Off, Required} {
		got, err := ParseMode(m.String())
		if err != nil || got != m {
			t.Errorf("%v: %v %v", m, got, err)
		}
	}
	if m, err := ParseMode(""); err != nil || m != BestEffort {
		t.Errorf("empty: %v %v", m, err)
	}
	if _, err := ParseMode("maybe"); err == nil || !strings.Contains(err.Error(), `"maybe"`) {
		t.Errorf("bad mode: %v", err)
	}
}
