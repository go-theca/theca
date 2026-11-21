package memlock

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// fake records the page-sized calls the package makes.
type fake struct {
	locked   map[uintptr]int // page -> times locked and not yet unlocked
	locks    int
	unlocks  int
	refuse   error
	refuseAt int // 1-based call that is refused; 0: every call when refuse != nil
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{locked: map[uintptr]int{}}
	restore := SetSyscalls(func(p unsafe.Pointer, n uintptr) error {
		f.locks++
		if f.refuse != nil && (f.refuseAt == 0 || f.refuseAt == f.locks) {
			return f.refuse
		}
		f.locked[uintptr(p)&^(pageSize-1)]++
		return nil
	}, func(p unsafe.Pointer, n uintptr) {
		f.unlocks++
		f.locked[uintptr(p)&^(pageSize-1)]--
	})
	t.Cleanup(func() {
		restore()
		SetMode(BestEffort)
		SetReporter(nil)
	})
	SetMode(BestEffort)
	SetReporter(nil)
	return f
}

// block is a page-aligned run of pages inside one live allocation.
func block(pages int) ([]byte, uintptr) {
	b := make([]byte, int(pageSize)*(pages+1))
	base := (uintptr(unsafe.Pointer(&b[0])) + pageSize - 1) &^ (pageSize - 1)
	off := base - uintptr(unsafe.Pointer(&b[0]))
	return b[off : off+uintptr(pages)*pageSize], base
}

func (f *fake) held() (n int) {
	for _, c := range f.locked {
		if c != 0 {
			n++
		}
	}
	return n
}

func TestLockCoversEveryPageOfTheRangeAndReleaseFreesThem(t *testing.T) {
	f := newFake(t)
	b, _ := block(3)
	r, err := Lock(unsafe.Pointer(&b[10]), uintptr(len(b))-20) // starts and ends mid-page: 3 pages
	if err != nil || r == nil {
		t.Fatalf("Lock: %v %v", r, err)
	}
	if f.locks != 3 || f.held() != 3 {
		t.Fatalf("%d calls, %d pages held, want 3 and 3", f.locks, f.held())
	}
	r.Release()
	r.Release() // a second release does nothing
	if f.unlocks != 3 || f.held() != 0 {
		t.Fatalf("%d unlocks, %d pages held after release", f.unlocks, f.held())
	}
}

func TestAPageSharedByTwoRegionsIsUnlockedByTheLastOne(t *testing.T) {
	f := newFake(t)
	b, _ := block(1)
	a, _ := Lock(unsafe.Pointer(&b[0]), 32)
	c, _ := Lock(unsafe.Pointer(&b[64]), 32)
	if f.locks != 1 {
		t.Fatalf("the second region locked the page again: %d calls", f.locks)
	}
	a.Release()
	if f.unlocks != 0 || f.held() != 1 {
		t.Fatal("the first release unlocked a page the second region still needs")
	}
	c.Release()
	if f.unlocks != 1 || f.held() != 0 {
		t.Fatal("the last release did not unlock the page")
	}
}

func TestSetPageSize(t *testing.T) {
	f := newFake(t)
	defer SetPageSize(1)()
	b, _ := block(8) // with 1-byte pages: 9 bytes, so the 5 locked stay inside the object (checkptr)
	r, _ := Lock(unsafe.Pointer(&b[0]), 5)
	if f.locks != 5 {
		t.Fatalf("%d calls with 1-byte pages, want 5", f.locks)
	}
	r.Release()
}

func TestReleaseOfAForgottenPageDoesNothing(t *testing.T) {
	f := newFake(t)
	b, _ := block(1)
	r, _ := Lock(unsafe.Pointer(&b[0]), 8)
	SetSyscalls(func(unsafe.Pointer, uintptr) error { return nil }, func(unsafe.Pointer, uintptr) {})()
	r.Release()
	if f.unlocks != 0 {
		t.Fatal("unlocked a page the counts had forgotten")
	}
}

func TestOffAndEmptyDoNothing(t *testing.T) {
	f := newFake(t)
	b, _ := block(1)
	SetMode(Off)
	if r, err := Lock(unsafe.Pointer(&b[0]), 8); r != nil || err != nil || f.locks != 0 {
		t.Fatalf("Off: %v %v %d", r, err, f.locks)
	}
	SetMode(BestEffort)
	if r, err := Lock(unsafe.Pointer(&b[0]), 0); r != nil || err != nil || f.locks != 0 {
		t.Fatalf("empty: %v %v %d", r, err, f.locks)
	}
	var nilRegion *Region
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("Release on a nil Region panicked: %v", p)
		}
	}()
	nilRegion.Release()
}

func TestABestEffortRefusalIsReportedOnceAndTheRestStillLocks(t *testing.T) {
	f := newFake(t)
	f.refuse, f.refuseAt = errors.New("cannot allocate memory"), 1
	var heard []error
	SetReporter(func(err error) { heard = append(heard, err) })
	b, _ := block(3)
	r, err := Lock(unsafe.Pointer(&b[0]), uintptr(len(b)))
	if err != nil {
		t.Fatalf("best effort returned %v", err)
	}
	if f.held() != 2 {
		t.Fatalf("%d pages held, want the 2 that were not refused", f.held())
	}
	f.refuseAt = 0
	if _, err := Lock(unsafe.Pointer(&b[0]), 1); err != nil { // page 0 is refused again: not reported twice
		t.Fatal(err)
	}
	if len(heard) != 1 || !strings.Contains(heard[0].Error(), "cannot allocate memory") {
		t.Fatalf("heard %v, want one report", heard)
	}
	if Failed() != nil {
		t.Fatal("Failed reports in best-effort mode")
	}
	r.Release()
	if f.held() != 0 { // pages 1 and 2 released; page 0 was never locked
		t.Fatalf("%d pages still held", f.held())
	}
}

func TestAnUnsupportedPlatformIsNotReported(t *testing.T) {
	f := newFake(t)
	f.refuse = errors.ErrUnsupported
	SetReporter(func(err error) { t.Errorf("reported %v", err) })
	b, _ := block(1)
	if r, err := Lock(unsafe.Pointer(&b[0]), 8); err != nil || r == nil {
		t.Fatalf("%v %v", r, err)
	}
}

func TestARefusalWithNoReporterIsSilent(t *testing.T) {
	f := newFake(t)
	f.refuse = errors.New("no")
	b, _ := block(1)
	if _, err := Lock(unsafe.Pointer(&b[0]), 8); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredTurnsARefusalIntoAnErrorAndHoldsNothing(t *testing.T) {
	f := newFake(t)
	SetMode(Required)
	f.refuse, f.refuseAt = errors.New("operation not permitted"), 3
	b, _ := block(3)
	r, err := Lock(unsafe.Pointer(&b[0]), uintptr(len(b)))
	if err == nil || r != nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("Required: %v %v", r, err)
	}
	if f.held() != 0 || f.unlocks != 2 {
		t.Fatalf("the two pages locked before the refusal were not given back: held %d, unlocks %d", f.held(), f.unlocks)
	}
	first := Failed()
	if first == nil {
		t.Fatal("Failed is nil after a refusal")
	}
	f.refuseAt = 0
	Lock(unsafe.Pointer(&b[0]), 8)
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
