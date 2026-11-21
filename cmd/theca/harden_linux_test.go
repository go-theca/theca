package main

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenPlatformLinux(t *testing.T) {
	sr, pc := setrlimit, prctl
	defer func() { setrlimit, prctl = sr, pc }()
	var gotRes int
	var gotLim unix.Rlimit
	var gotOpt int
	var gotArg uintptr
	setrlimit = func(res int, l *unix.Rlimit) error { gotRes, gotLim = res, *l; return nil }
	prctl = func(opt int, a2, _, _, _ uintptr) error { gotOpt, gotArg = opt, a2; return nil }
	if err := hardenPlatform(); err != nil {
		t.Fatal(err)
	}
	if gotRes != unix.RLIMIT_CORE || gotLim != (unix.Rlimit{}) || gotOpt != unix.PR_SET_DUMPABLE || gotArg != 0 {
		t.Fatalf("setrlimit(%d,%v) prctl(%d,%d)", gotRes, gotLim, gotOpt, gotArg)
	}
	// One refusal does not skip the other: both are tried and both reported.
	setrlimit = func(int, *unix.Rlimit) error { return errors.New("rlimit refused") }
	prctl = func(int, uintptr, uintptr, uintptr, uintptr) error { return errors.New("prctl refused") }
	err := hardenPlatform()
	if err == nil || !strings.Contains(err.Error(), "rlimit refused") || !strings.Contains(err.Error(), "prctl refused") {
		t.Fatalf("%v", err)
	}
}
