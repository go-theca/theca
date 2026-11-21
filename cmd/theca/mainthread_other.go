//go:build !darwin

package main

import "context"

// serveMainLoop has no run loop to serve off darwin: Linux asks logind over
// D-Bus.
func serveMainLoop(context.Context) error { return nil }
