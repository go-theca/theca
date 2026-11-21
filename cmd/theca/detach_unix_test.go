//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdStreams(t *testing.T) {
	if n := len(stdStreams()); n != 3 {
		t.Fatal(n)
	}
}

func TestDetachAndLock(t *testing.T) {
	dir := t.TempDir()
	// detachTo points every stream at /dev/null and closes what it held.
	a, _ := os.Create(filepath.Join(dir, "a"))
	b, _ := os.Create(filepath.Join(dir, "b"))
	if err := detachTo(&a, &b); err != nil {
		t.Fatal(err)
	}
	if a.Name() != os.DevNull || b.Name() != os.DevNull {
		t.Fatal(a.Name(), b.Name())
	}
	saved := devNull
	t.Cleanup(func() {
		devNull = saved
		stdStreams = func() []**os.File { return []**os.File{&os.Stdin, &os.Stdout, &os.Stderr} }
	})
	devNull = filepath.Join(dir, "missing", "null")
	if err := detachTo(&a); err == nil {
		t.Fatal("open error lost")
	}
	devNull = saved
	in, out, er := a, b, a
	stdStreams = func() []**os.File { return []**os.File{&in, &out, &er} }
	if err := detachStdio(); err != nil {
		t.Fatal(err)
	}

	f := filepath.Join(dir, "c")
	os.WriteFile(f, nil, 0o600)
	release, err := lockContainer(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockContainer(f); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("second lock: %v", err)
	}
	release()
	release, err = lockContainer(f)
	if err != nil {
		t.Fatal("lock not released:", err)
	}
	release()
	if _, err := lockContainer(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("missing file locked")
	}
	oldF := flock
	t.Cleanup(func() { flock = oldF })
	flock = func(int, int) error { return errors.New("EIO") }
	if _, err := lockContainer(f); err == nil || strings.Contains(err.Error(), "already open") {
		t.Fatalf("other flock error: %v", err)
	}
}
