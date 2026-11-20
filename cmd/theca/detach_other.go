//go:build !unix

package main

import "errors"

var errNoDaemon = errors.New("theca open/close need Unix sockets and sessions: not available on this system yet (use theca serve --mount)")

func detachStdio() error { return errNoDaemon }

func lockContainer(string) (func(), error) { return nil, errNoDaemon }
