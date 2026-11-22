// Package pin is theca's policy over go-authn/harden/memlock: what a refusal to
// pin the pages that hold key material means (go-theca/theca#68). The locking
// itself, its page counts and its platform calls live in harden; this package
// holds only the --mlock flag's three meanings.
//
// Locking is best effort by default: a refusal (RLIMIT_MEMLOCK) is reported once
// and the key stays unlocked; a platform with no page lock is not reported at
// all. In Required mode a refusal is an error instead.
package pin

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/go-authn/harden/memlock"
)

// Mode says what a refusal means.
type Mode int

const (
	// BestEffort locks when it can and reports one refusal (the default).
	BestEffort Mode = iota
	// Off never calls mlock.
	Off
	// Required turns a refusal into an error.
	Required
)

// String names the mode as the --mlock flag spells it.
func (m Mode) String() string {
	switch m {
	case Off:
		return "off"
	case Required:
		return "required"
	}
	return "auto"
}

// ParseMode reads the --mlock flag: auto, off or required.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "auto":
		return BestEffort, nil
	case "off":
		return Off, nil
	case "required":
		return Required, nil
	}
	return BestEffort, fmt.Errorf("--mlock %q: want auto, off or required", s)
}

var (
	mu       sync.Mutex
	locker   = memlock.Default
	mode     = BestEffort
	report   func(error)
	reported bool
	failed   error
)

// SetLocker replaces the harden Locker (and so its system calls and page
// counts) and returns the function that puts the real one back. For tests of
// this package and of its callers, which must make a refusal happen on any
// machine: memlock.NewLocker(memlock.Syscalls{...}, 1) makes the lock of ANY
// allocation reach the fake.
func SetLocker(l *memlock.Locker) (restore func()) {
	mu.Lock()
	defer mu.Unlock()
	old := locker
	locker = l
	return func() {
		mu.Lock()
		locker = old
		mu.Unlock()
	}
}

// SetMode chooses what a refusal means and forgets earlier refusals.
func SetMode(m Mode) {
	mu.Lock()
	mode, reported, failed = m, false, nil
	mu.Unlock()
}

// Current is the mode in force.
func Current() Mode {
	mu.Lock()
	defer mu.Unlock()
	return mode
}

// SetReporter names who hears of a refusal in BestEffort mode, once per
// process. nil: nobody.
func SetReporter(f func(error)) {
	mu.Lock()
	report, reported = f, false
	mu.Unlock()
}

// Failed is the first refusal of this process in Required mode, nil otherwise
// (only Required mode records one, and SetMode forgets it). Callers that cannot
// return an error at the point of locking check it after.
func Failed() error {
	mu.Lock()
	defer mu.Unlock()
	return failed
}

// hear passes the first refusal of the process to the reporter. A platform
// without a page lock is not a refusal worth a warning on every start.
func hear(err error) {
	mu.Lock()
	f := report
	first := !errors.Is(err, errors.ErrUnsupported) && !reported && f != nil
	if first {
		reported = true
	}
	mu.Unlock()
	if first {
		f(err)
	}
}

// Lock pins the pages holding [p, p+n), p being inside a live object. In
// BestEffort mode it returns the region of the pages it did lock and nil; the
// first refusal goes to the reporter. In Required mode a refusal returns an
// error and holds nothing. In Off mode, and for n == 0, it does nothing and
// returns a nil region (whose Release is safe).
func Lock(p unsafe.Pointer, n uintptr) (*memlock.Region, error) {
	mu.Lock()
	m, l := mode, locker
	mu.Unlock()
	if m == Off || n == 0 {
		return nil, nil
	}
	if m == Required {
		r, err := l.Lock(p, n)
		if err != nil {
			mu.Lock()
			if failed == nil {
				failed = err
			}
			mu.Unlock()
			return nil, err
		}
		return r, nil
	}
	return l.LockBestEffort(p, n, hear), nil
}
