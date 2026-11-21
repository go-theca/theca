//go:build darwin

package main

import (
	"context"
	"runtime"

	"github.com/go-macos/objc"
)

// init pins the main goroutine to the main OS thread, the only one whose run
// loop receives distributed and workspace notifications (see objc.Observe).
// Package initialisation is early enough: nothing has yet given the scheduler a
// chance to move the main goroutine.
func init() { runtime.LockOSThread() }

func serveMainLoop(ctx context.Context) error { return objc.RunMainLoop(ctx) }
