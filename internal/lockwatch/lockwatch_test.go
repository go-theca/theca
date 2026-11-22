package lockwatch

import (
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
