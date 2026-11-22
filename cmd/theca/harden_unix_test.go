//go:build linux || darwin

package main

import (
	"errors"
	"testing"
)

// The calls themselves are tested in go-authn/harden/memlock, in a child
// process; here the result is passed on as it is.
func TestHardenPlatformPassesOnDisableDumps(t *testing.T) {
	saved := disableDumps
	defer func() { disableDumps = saved }()
	called := 0
	disableDumps = func() error { called++; return nil }
	if err := hardenPlatform(); err != nil || called != 1 {
		t.Fatalf("%v after %d calls", err, called)
	}
	want := errors.New("rlimit refused")
	disableDumps = func() error { return want }
	if err := hardenPlatform(); err != want {
		t.Fatalf("%v", err)
	}
}
