//go:build !linux && !darwin

package main

import "testing"

func TestHardenPlatformIsANoOpHere(t *testing.T) {
	if err := hardenPlatform(); err != nil {
		t.Fatal(err)
	}
}
