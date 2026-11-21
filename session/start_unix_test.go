//go:build unix

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// init makes the test binary double as the background process: Start runs this
// binary with THECA_FAKE_DAEMON set, and it answers on descriptor 3 the way
// `theca _serve` does.
func init() {
	mode := os.Getenv("THECA_FAKE_DAEMON")
	if mode == "" {
		return
	}
	ready := os.NewFile(3, "ready")
	switch mode {
	case "ok":
		Report(ready, Response{OK: true, Info: &Info{Name: os.Args[2], Mount: "/Volumes/THECA"}})
	case "touch-err":
		fmt.Fprintln(os.Stderr, "touch your key")
		fmt.Fprintln(os.Stderr, strings.Repeat("x", 100000)) // beyond the scanner's line limit
		fmt.Fprintln(os.Stderr, "after")
		Report(ready, Response{Error: "wrong password"})
	case "err":
		Report(ready, Response{Error: "wrong password"})
	case "stdin":
		// The process has no terminal: reading stdin ends at once.
		b := make([]byte, 1)
		n, _ := os.Stdin.Read(b)
		Report(ready, Response{OK: n == 0, Info: &Info{Name: "stdin"}, Error: "stdin is open"})
	case "hang":
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

type notices struct {
	mu    sync.Mutex
	lines []string
}

func (n *notices) add(s string) {
	n.mu.Lock()
	n.lines = append(n.lines, s)
	n.mu.Unlock()
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestStart(t *testing.T) {
	exe := self(t)
	ctx := context.Background()

	t.Setenv("THECA_FAKE_DAEMON", "ok")
	i, err := Start(ctx, exe, "bio", nil)
	if err != nil || i.Mount != "/Volumes/THECA" || i.Name != "bio" {
		t.Fatalf("%+v %v", i, err)
	}
	if i, err = Start(ctx, exe, "bio", func(string) {}); err != nil || i.Name != "bio" {
		t.Fatalf("%+v %v", i, err)
	}

	t.Setenv("THECA_FAKE_DAEMON", "stdin")
	if i, err = Start(ctx, exe, "bio", nil); err != nil || i.Name != "stdin" {
		t.Fatalf("stdin not /dev/null: %+v %v", i, err)
	}

	t.Setenv("THECA_FAKE_DAEMON", "err")
	if _, err := Start(ctx, exe, "bio", nil); err == nil || err.Error() != "wrong password" {
		t.Fatal(err)
	}

	t.Setenv("THECA_FAKE_DAEMON", "die")
	if _, err := Start(ctx, exe, "bio", nil); err == nil || !strings.Contains(err.Error(), "without opening") {
		t.Fatal(err)
	}
}

func TestStartNotices(t *testing.T) {
	exe := self(t)
	t.Setenv("THECA_FAKE_DAEMON", "touch-err")
	var n notices
	_, err := Start(context.Background(), exe, "bio", n.add)
	if err == nil || err.Error() != "wrong password" {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	// The long line is dropped by the scanner and drained; what came before arrives.
	if len(n.lines) == 0 || n.lines[0] != "touch your key" {
		t.Fatalf("notices %q", n.lines)
	}
	// A nil callback is allowed with output too.
	t.Setenv("THECA_FAKE_DAEMON", "touch-err")
	if _, err := Start(context.Background(), exe, "bio", nil); err == nil {
		t.Fatal("no error")
	}
}

func TestStartHang(t *testing.T) {
	exe := self(t)
	t.Setenv("THECA_FAKE_DAEMON", "hang")
	for _, notice := range []func(string){nil, func(string) {}} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		_, err := Start(ctx, exe, "bio", notice)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 20*time.Second {
			t.Fatalf("hang: %v after %v", err, time.Since(start))
		}
	}
}

func TestStartAttached(t *testing.T) {
	exe := self(t)
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	t.Setenv("THECA_FAKE_DAEMON", "ok")
	i, err := StartAttached(context.Background(), exe, "bio", null, null)
	if err != nil || i.Mount != "/Volumes/THECA" {
		t.Fatalf("%+v %v", i, err)
	}
	// Without streams the process inherits nothing.
	if i, err = StartAttached(context.Background(), exe, "bio", nil, nil); err != nil || i.Name != "bio" {
		t.Fatalf("%+v %v", i, err)
	}
	t.Setenv("THECA_FAKE_DAEMON", "err")
	if _, err := StartAttached(context.Background(), exe, "bio", null, null); err == nil || err.Error() != "wrong password" {
		t.Fatal(err)
	}
}

func TestStartFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nothing")
	for _, notice := range []func(string){nil, func(string) {}} {
		if _, err := Start(context.Background(), missing, "bio", notice); err == nil {
			t.Fatal("missing binary started")
		}
	}
	if _, err := StartAttached(context.Background(), missing, "bio", nil, nil); err == nil {
		t.Fatal("missing binary started")
	}

	boom := errors.New("no pipe")
	saved := osPipe
	t.Cleanup(func() { osPipe = saved })
	calls := 0
	for fail := 1; fail <= 2; fail++ {
		calls = 0
		osPipe = func() (*os.File, *os.File, error) {
			calls++
			if calls == fail {
				return nil, nil, boom
			}
			return saved()
		}
		if _, err := Start(context.Background(), missing, "bio", nil); !errors.Is(err, boom) {
			t.Fatalf("pipe %d: %v", fail, err)
		}
	}
}
