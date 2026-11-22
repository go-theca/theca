package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNullStreams(t *testing.T) {
	dir := t.TempDir()
	a, _ := os.Create(filepath.Join(dir, "a"))
	b, _ := os.Create(filepath.Join(dir, "b"))
	if err := nullStreams(&a, &b); err != nil {
		t.Fatal(err)
	}
	if a != b || a.Name() != os.DevNull {
		t.Errorf("streams = %v, %v", a.Name(), b.Name())
	}
	old := devNull
	defer func() { devNull = old }()
	devNull = filepath.Join(dir, "missing", "null")
	if err := nullStreams(&a); err == nil {
		t.Error("missing null device accepted")
	}
	if got := stdStreams(); len(got) != 3 {
		t.Errorf("stdStreams = %d", len(got))
	}
}

func TestLockContainerWith(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := errors.New("other")
	isBusy := func(err error) bool { return err == errBusy }
	if _, err := lockContainerWith(filepath.Join(path, "nope"), nil, isBusy); err == nil {
		t.Error("open error not reported")
	}
	if _, err := lockContainerWith(path, func(*os.File) error { return errBusy }, isBusy); err != errBusy {
		t.Errorf("busy: %v", err)
	}
	if _, err := lockContainerWith(path, func(*os.File) error { return other }, isBusy); err != other {
		t.Errorf("other: %v", err)
	}
	release, err := lockContainerWith(path, func(*os.File) error { return nil }, isBusy)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
