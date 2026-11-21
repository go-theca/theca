package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// osPipe is the seam the tests replace.
var osPipe = os.Pipe

// Start runs `exe _serve NAME` as a background process and waits until the
// container of the profile NAME is unlocked and mounted, or the attempt failed.
// exe is the theca binary (os.Executable() for theca itself).
//
// The process has no terminal here: its standard input is /dev/null, and each
// line it writes to its standard error while it unlocks (the security key's
// "touch" notice, for one) is handed to notice, in order, on another goroutine,
// until Start returns. A nil notice drops them. ctx bounds the wait: when it
// ends, the process is killed. On success the process keeps running, detached,
// and Info says where the container is mounted.
//
// extra are further command-line arguments for the child, after the name.
func Start(ctx context.Context, exe, name string, notice func(string), extra ...string) (Info, error) {
	return startProcess(ctx, exe, name, nil, nil, true, notice, extra)
}

// StartAttached is Start for a terminal: the process inherits in and out as its
// standard input, output and error until the container is open, so that a
// notice and a PIN prompt reach the person.
func StartAttached(ctx context.Context, exe, name string, in, out *os.File, extra ...string) (Info, error) {
	return startProcess(ctx, exe, name, in, out, false, nil, extra)
}

func startProcess(ctx context.Context, exe, name string, in, out *os.File, capture bool, notice func(string), extra []string) (Info, error) {
	r, w, err := osPipe()
	if err != nil {
		return Info{}, err
	}
	defer r.Close()
	child := exec.Command(exe, append([]string{"_serve", name}, extra...)...)
	if in != nil {
		child.Stdin = in
	}
	var lines *noticeReader
	var ew *os.File
	if capture {
		var er *os.File
		er, ew, err = osPipe()
		if err != nil {
			w.Close()
			return Info{}, err
		}
		lines = newNoticeReader(er, notice)
		child.Stdout, child.Stderr = ew, ew
	} else if out != nil {
		child.Stdout, child.Stderr = out, out
	}
	child.ExtraFiles = []*os.File{w}
	err = child.Start()
	w.Close()
	if lines != nil {
		// The child has its own copy of the write end; ours must go for the
		// reader to see the end of the stream.
		ew.Close()
	}
	if err != nil {
		if lines != nil {
			lines.r.Close()
		}
		return Info{}, err
	}
	if lines != nil {
		go lines.run()
		defer lines.mute()
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			child.Process.Kill()
		case <-stop:
		}
	}()
	resp, err := DecodeResponse(r)
	if err != nil || !resp.OK || resp.Info == nil {
		child.Process.Kill()
		child.Wait()
		if lines != nil {
			lines.stop()
		}
		switch {
		case ctx.Err() != nil:
			return Info{}, fmt.Errorf("open %s: %w", name, ctx.Err())
		case err == nil && resp.Error != "":
			return Info{}, errors.New(resp.Error)
		}
		return Info{}, fmt.Errorf("open %s: the background process ended without opening the container", name)
	}
	child.Process.Release()
	return *resp.Info, nil
}

// noticeReader hands the lines of a stream to a callback, one at a time, and
// never after it has been muted.
type noticeReader struct {
	r      *os.File
	notice func(string)

	mu    sync.Mutex
	muted bool
	done  chan struct{}
}

func newNoticeReader(r *os.File, notice func(string)) *noticeReader {
	return &noticeReader{r: r, notice: notice, done: make(chan struct{})}
}

func (n *noticeReader) run() {
	defer close(n.done)
	defer n.r.Close()
	sc := bufio.NewScanner(n.r)
	for sc.Scan() {
		n.mu.Lock()
		if !n.muted && n.notice != nil {
			n.notice(sc.Text())
		}
		n.mu.Unlock()
	}
	// A line longer than the scanner's limit ends the loop; drain the rest so
	// the process never blocks on a full pipe.
	io.Copy(io.Discard, n.r)
}

// mute stops any further callback; one already running has finished when it
// returns (the lock is held across the call).
func (n *noticeReader) mute() {
	n.mu.Lock()
	n.muted = true
	n.mu.Unlock()
}

// stop waits for the stream to end (the process is gone), delivering what was
// written, and then mutes.
func (n *noticeReader) stop() {
	<-n.done
	n.mute()
}
