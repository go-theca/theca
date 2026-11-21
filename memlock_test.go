package theca

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/go-theca/theca/internal/memlock"
)

// lockCalls runs fn with a page size of one byte, so that no two keys share a
// page and every lock reaches the system call, and with the call number n from
// which every lock is refused (0: none is). It returns how many calls were made.
func lockCalls(n int, fn func()) (calls int) {
	defer memlock.SetPageSize(1)()
	restore := memlock.SetSyscalls(func(unsafe.Pointer, uintptr) error {
		calls++
		if n > 0 && calls >= n {
			return errors.New("operation not permitted")
		}
		return nil
	}, func(unsafe.Pointer, uintptr) {})
	memlock.SetMode(memlock.Required)
	defer func() { restore(); memlock.SetMode(memlock.BestEffort) }()
	fn()
	return calls
}

// Under --mlock=required a key that cannot be pinned is the answer, never "no
// slot opens". The refusal is made to fall everywhere along an Open: on the
// wrap key of an early slot trial, and after a slot opened, on the next.
func TestRequiredMlockRefusalIsNotNoMatch(t *testing.T) {
	_, f, _ := create(t, PolicyAny)
	total := lockCalls(0, func() {
		c, err := Open(ctx, f, pwUnlock(), OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	})
	if total < 100 {
		t.Fatalf("an Open made only %d lock calls", total)
	}
	for n := 1; n <= total; n += 7 {
		lockCalls(n, func() {
			c, err := Open(ctx, f, pwUnlock(), OpenOptions{})
			if err == nil {
				c.Close()
				t.Fatalf("n=%d of %d: Open succeeded although a lock was refused", n, total)
			}
			if errors.Is(err, ErrNoMatch) || !strings.Contains(err.Error(), "operation not permitted") {
				t.Fatalf("n=%d of %d: %v", n, total, err)
			}
		})
	}
}
