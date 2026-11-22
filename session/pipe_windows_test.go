//go:build windows

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func testPipeName(t *testing.T) string {
	return fmt.Sprintf("t%d-%d", os.Getpid(), time.Now().UnixNano())
}

func TestPipeRoundTrip(t *testing.T) {
	path, err := SocketPath(testPipeName(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, `\\.\pipe\theca-S-1-`) {
		t.Fatalf("path = %q", path)
	}
	l, err := listenEndpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if err := authorize(c); err != nil {
			c.Write([]byte("refused: " + err.Error() + "\n"))
			return
		}
		c.Write([]byte("hello\n"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialEndpoint(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("line = %q, %v", line, err)
	}
	// A second listener on a live pipe is ErrAlreadyOpen.
	if _, err := listenEndpoint(path); !errors.Is(err, ErrAlreadyOpen) {
		t.Errorf("second listener: %v", err)
	}
	removeEndpoint(path)
}

func TestPipeSeamErrors(t *testing.T) {
	old := userSID
	defer func() { userSID = old }()
	boom := errors.New("no sid")
	userSID = func() (string, error) { return "", boom }
	if _, err := SocketPath("x"); !errors.Is(err, boom) {
		t.Errorf("SocketPath: %v", err)
	}
	if _, err := listenEndpoint(`\\.\pipe\theca-x`); !errors.Is(err, boom) {
		t.Errorf("listenEndpoint: %v", err)
	}
	if err := authorize(nil); !errors.Is(err, boom) {
		t.Errorf("authorize: %v", err)
	}
}

// A client whose SID is not ours is refused (the SID is swapped for the check).
func TestPipeRefusesOtherSID(t *testing.T) {
	path, _ := SocketPath(testPipeName(t))
	l, err := listenEndpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	res := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			res <- err
			return
		}
		defer c.Close()
		res <- authorizeSID(c, "S-1-5-18", clientSID)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialEndpoint(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-res; !errors.Is(err, ErrPeer) {
		t.Errorf("other SID: %v", err)
	}
}

func TestClientSIDErrors(t *testing.T) {
	if _, err := clientSID(0); err == nil {
		t.Error("handle 0 accepted")
	}
}

func TestListenPipeFailure(t *testing.T) {
	old := listenPipe
	defer func() { listenPipe = old }()
	boom := errors.New("listen")
	listenPipe = func(string, *winio.PipeConfig) (net.Listener, error) { return nil, boom }
	if _, err := listenEndpoint(`\\.\pipe\theca-nobody-` + testPipeName(t)); !errors.Is(err, boom) {
		t.Errorf("listen failure: %v", err)
	}
	listenPipe = func(string, *winio.PipeConfig) (net.Listener, error) {
		return nil, fmt.Errorf("open: %w", windows.ERROR_ACCESS_DENIED)
	}
	if _, err := listenEndpoint(`\\.\pipe\theca-nobody-` + testPipeName(t)); !errors.Is(err, ErrAlreadyOpen) {
		t.Errorf("first-instance refusal: %v", err)
	}
}

func TestReadyFileWindows(t *testing.T) {
	t.Setenv(ReadyEnv, "")
	if f := ReadyFile(); f != nil {
		t.Errorf("ReadyFile without the variable = %v", f)
	}
	t.Setenv(ReadyEnv, "123456")
	if f := ReadyFile(); f == nil || f.Name() != "ready" {
		t.Errorf("ReadyFile = %v", f)
	}
	if _, ok := os.LookupEnv(ReadyEnv); ok {
		t.Error("the variable stays set")
	}
}

func TestJobLimits(t *testing.T) {
	l, err := jobLimits() // the real job of the test process, if it has one
	t.Logf("job limits %#x, err %v, breakaway flag %#x", l, err, breakawayFlag(l, err))
	old := queryJob
	defer func() { queryJob = old }()
	boom := errors.New("no job")
	queryJob = func(windows.Handle, int32, uintptr, uint32, *uint32) error { return boom }
	if _, err := jobLimits(); !errors.Is(err, boom) {
		t.Errorf("jobLimits error: %v", err)
	}
}

func TestInheritReadyWindows(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	c := exec.Command("cmd")
	if err := inheritReady(c, w); err != nil {
		t.Fatal(err)
	}
	if c.SysProcAttr == nil || len(c.SysProcAttr.AdditionalInheritedHandles) != 1 {
		t.Fatalf("SysProcAttr = %+v", c.SysProcAttr)
	}
	found := false
	for _, e := range c.Env {
		if strings.HasPrefix(e, ReadyEnv+"=") {
			found = true
		}
	}
	if !found {
		t.Error("ReadyEnv not set")
	}
	// A closed file's handle cannot be made inheritable.
	cl, cw, _ := os.Pipe()
	cl.Close()
	cw.Close()
	if err := inheritReady(exec.Command("cmd"), cw); err == nil {
		t.Error("closed handle accepted")
	}
}
