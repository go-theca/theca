//go:build !unix && !windows

package main

import "errors"

var errNoDaemon = errors.New("theca open/close need Unix sockets or Windows named pipes: not available on this system yet (use theca serve --mount)")

func detachStdio() error { return errNoDaemon }

func lockContainer(string) (func(), error) { return nil, errNoDaemon }
