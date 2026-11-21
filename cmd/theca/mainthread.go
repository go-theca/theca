package main

import "context"

// runMainLoop serves the main thread's run loop until ctx ends (darwin: the
// loop the screen-lock, sleep and session-end notifications arrive on; elsewhere
// it returns at once). Tests replace it.
var runMainLoop = serveMainLoop

// onMainThread runs work on another goroutine and gives the main goroutine,
// which mainthread_darwin.go locked to the main OS thread, to the run loop for
// as long as work lasts. It returns work's error. A loop that cannot run (not
// the main thread) is not an error here: the lock watcher proves its observers
// and polls instead when nothing delivers them.
func onMainThread(work func() error) error {
	ctx, stop := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- work()
		stop()
	}()
	_ = runMainLoop(ctx)
	return <-errc
}
