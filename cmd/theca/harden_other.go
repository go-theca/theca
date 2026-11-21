//go:build !linux && !darwin

package main

// hardenPlatform does nothing here: no core limit or debugger refusal is
// available through a call this program makes (go-theca/theca#68).
func hardenPlatform() error { return nil }
