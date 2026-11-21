// Package memlock pins the pages that hold key material in RAM, so the
// operating system cannot write them to swap (go-theca/theca#68).
//
// mlock works on whole pages and does not count: one munlock of a page undoes
// every mlock of it. Two small objects often share a page (a master secret and
// the wrap key that is wiped a moment later), so each page carries a count here
// and is unlocked only when the last region that locked it is released.
//
// Locking is best effort by default: a refusal (RLIMIT_MEMLOCK, a platform with
// no mlock) is reported once and the key stays unlocked. In Required mode a
// refusal is an error instead.
//
// A page address is kept as a number, never as a pointer: the page that holds
// an object also holds the end of its neighbour, and a pointer to a page start
// can point into a freed object, which the garbage collector refuses. The
// system calls are given pointers INSIDE the object that is being locked.
package memlock

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"
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

// Seams: the system calls, and the page size. Tests replace them.
var (
	sysLock   = lockRange
	sysUnlock = unlockRange
	pageSize  = uintptr(os.Getpagesize())
)

// SetSyscalls replaces the system calls and returns the function that puts the
// real ones back. For tests of this package and of its callers, which must make
// a refusal happen on any machine. The page counts are forgotten at both ends:
// a page locked by a test double is not locked, and a Release of a forgotten
// page does nothing.
func SetSyscalls(lock func(unsafe.Pointer, uintptr) error, unlock func(unsafe.Pointer, uintptr)) (restore func()) {
	mu.Lock()
	defer mu.Unlock()
	l, u := sysLock, sysUnlock
	sysLock, sysUnlock = lock, unlock
	clear(counts)
	return func() {
		mu.Lock()
		sysLock, sysUnlock = l, u
		clear(counts)
		mu.Unlock()
	}
}

// SetPageSize makes a "page" size bytes and returns the function that restores
// the real one: with 1, no two objects share a page, so a test can make the
// lock of ANY allocation reach the system call. For tests only, with
// SetSyscalls (which forgets the page counts that a size change would corrupt).
func SetPageSize(size uintptr) (restore func()) {
	mu.Lock()
	defer mu.Unlock()
	old := pageSize
	pageSize = size
	return func() {
		mu.Lock()
		pageSize = old
		mu.Unlock()
	}
}

var (
	mu       sync.Mutex
	mode     = BestEffort
	report   func(error)
	reported bool
	failed   error
	counts   = map[uintptr]int{}
)

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

// Failed is the first refusal of this process in Required mode, nil otherwise.
// Callers that cannot return an error at the point of locking check it after.
func Failed() error {
	mu.Lock()
	defer mu.Unlock()
	if mode != Required {
		return nil
	}
	return failed
}

// span is the part of one page that an object covers.
type span struct {
	page uintptr
	p    unsafe.Pointer // inside the object
	n    uintptr
}

// Region is the set of pages one Lock call holds. It keeps the object alive.
type Region struct{ spans []span }

// release drops one count on each span; mu is held.
func (r *Region) release() {
	for _, s := range r.spans {
		c, ok := counts[s.page]
		if !ok { // forgotten by SetSyscalls: its lock was a test double's
			continue
		}
		if c--; c == 0 {
			delete(counts, s.page)
			sysUnlock(s.p, s.n)
		} else {
			counts[s.page] = c
		}
	}
	r.spans = nil
}

// Release unlocks the pages that no other region holds. Safe on nil, and a
// second call does nothing.
func (r *Region) Release() {
	if r == nil {
		return
	}
	mu.Lock()
	r.release()
	mu.Unlock()
}

// Lock pins the pages holding [p, p+n), p being inside a live object. In
// BestEffort mode it returns the region of the pages it did lock and nil; the
// first refusal goes to the reporter. In Required mode a refusal returns an
// error and holds nothing. In Off mode it does nothing.
func Lock(p unsafe.Pointer, n uintptr) (*Region, error) {
	mu.Lock()
	defer mu.Unlock()
	if mode == Off || n == 0 {
		return nil, nil
	}
	r := &Region{}
	start, end := uintptr(p), uintptr(p)+n
	for pg := start &^ (pageSize - 1); pg < end; pg += pageSize {
		lo, hi := max(start, pg), min(end, pg+pageSize)
		s := span{page: pg, p: unsafe.Add(p, lo-start), n: hi - lo}
		if counts[pg] == 0 {
			if err := sysLock(s.p, s.n); err != nil {
				err = fmt.Errorf("memlock: %w", err)
				if mode == Required {
					r.release()
					if failed == nil {
						failed = err
					}
					return nil, err
				}
				if !errors.Is(err, errors.ErrUnsupported) && !reported && report != nil {
					reported = true
					report(err)
				}
				continue
			}
		}
		counts[pg]++
		r.spans = append(r.spans, s)
	}
	return r, nil
}
