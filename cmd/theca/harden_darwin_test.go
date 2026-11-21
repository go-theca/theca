package main

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenPlatformDarwin(t *testing.T) {
	sr, da := setrlimit, denyAttach
	defer func() { setrlimit, denyAttach = sr, da }()
	var gotRes int
	var gotLim unix.Rlimit
	denied := 0
	setrlimit = func(res int, l *unix.Rlimit) error { gotRes, gotLim = res, *l; return nil }
	denyAttach = func() error { denied++; return nil }
	if err := hardenPlatform(); err != nil {
		t.Fatal(err)
	}
	if gotRes != unix.RLIMIT_CORE || gotLim != (unix.Rlimit{}) || denied != 1 {
		t.Fatalf("setrlimit(%d,%v) denyAttach x%d", gotRes, gotLim, denied)
	}
	setrlimit = func(int, *unix.Rlimit) error { return errors.New("rlimit refused") }
	denyAttach = func() error { return errors.New("deny refused") }
	err := hardenPlatform()
	if err == nil || !strings.Contains(err.Error(), "rlimit refused") || !strings.Contains(err.Error(), "deny refused") {
		t.Fatalf("%v", err)
	}
}
