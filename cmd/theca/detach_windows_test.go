//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLockContainerWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c")
	if err := os.WriteFile(path, []byte("container bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := lockContainer(path)
	if err != nil {
		t.Fatal(err)
	}
	// The container stays readable while locked.
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "container bytes" {
		t.Errorf("read while locked: %q, %v", b, err)
	}
	if _, err := lockContainer(path); !errors.Is(err, errBusy) {
		t.Errorf("second lock: %v", err)
	}
	release()
	release2, err := lockContainer(path)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	release2()

	old := lockFileEx
	defer func() { lockFileEx = old }()
	boom := errors.New("boom")
	lockFileEx = func(windows.Handle, uint32, uint32, uint32, uint32, *windows.Overlapped) error { return boom }
	if _, err := lockContainer(path); !errors.Is(err, boom) {
		t.Errorf("other error: %v", err)
	}
}

func TestDetachStdioWindows(t *testing.T) {
	// The streams are stand-ins: closing the real ones would end the test's own
	// output.
	a, _ := os.Create(filepath.Join(t.TempDir(), "a"))
	old := stdStreams
	defer func() { stdStreams = old }()
	stdStreams = func() []**os.File { return []**os.File{&a} }
	if err := detachStdio(); err != nil {
		t.Fatal(err)
	}
	if a.Name() != os.DevNull {
		t.Errorf("stream = %q", a.Name())
	}
}

func TestHardenPlatformWindows(t *testing.T) {
	old := setErrorMode
	defer func() { setErrorMode = old }()
	var got uint32
	setErrorMode = func(m uint32) uint32 { got = m; return 0 }
	if err := hardenPlatform(); err != nil {
		t.Fatal(err)
	}
	want := uint32(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX | windows.SEM_NOOPENFILEERRORBOX)
	if got != want {
		t.Errorf("mode = %#x, want %#x", got, want)
	}
}
