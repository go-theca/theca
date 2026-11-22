// Package session is the conversation between `theca close` / `theca status`
// (or a GUI) and the background process that holds an unlocked container.
//
// The socket is a Unix socket named after the profile, in a directory only its
// owner can enter (mode 0700), itself mode 0600; the server also asks the
// kernel who is on the other end (SO_PEERCRED, LOCAL_PEERCRED) and refuses any
// user but its own. A message is one JSON line of at most MaxMessage bytes, with
// no unknown field; a longer one is refused without being read to its end.
// On Windows the channel is a named pipe, \\.\pipe\theca-SID-NAME, whose
// security descriptor grants access to the user's SID alone and refuses remote
// clients; the server also compares the SID of the client's process with its
// own (pipe_windows.go, pipesid.go).
// Nothing secret crosses it: a request is an operation name, a response says
// where the share is mounted.
package session

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// MaxMessage bounds a request and a response, newline included.
const MaxMessage = 4096

// Operations.
const (
	OpStatus = "status"
	OpClose  = "close"
)

// Errors.
var (
	ErrAlreadyOpen = errors.New("session: this container is already open")
	ErrNotOpen     = errors.New("session: not open")
	ErrTooLong     = errors.New("session: message longer than the limit")
	ErrPeer        = errors.New("session: peer is not the owner of the session")
)

// Request is what a client sends.
type Request struct {
	Op string `json:"op"`
}

// Info says what is open. It holds no secret: the share's own account is not
// here, it stays in the process.
type Info struct {
	Name  string `json:"name"`
	File  string `json:"file"`
	Mount string `json:"mount"`
	URL   string `json:"url"`
	Since int64  `json:"since"` // Unix seconds
	PID   int    `json:"pid"`
}

// Response is what the server answers.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Info  *Info  `json:"info,omitempty"`
}

// Handler is what the process behind the socket does.
type Handler interface {
	Status() Info
	// Close unmounts, commits and wipes, and returns when that is done.
	Close() error
}

// decode reads one line of at most MaxMessage bytes into v, refusing unknown
// fields and trailing data.
func decode(r io.Reader, v any) error {
	br := bufio.NewReaderSize(io.LimitReader(r, MaxMessage+1), MaxMessage+1)
	line, err := br.ReadBytes('\n')
	if len(line) > MaxMessage {
		return ErrTooLong
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if dec.More() {
		return errors.New("session: data after the message")
	}
	return nil
}

// DecodeRequest parses and validates one request line.
func DecodeRequest(r io.Reader) (Request, error) {
	var q Request
	if err := decode(r, &q); err != nil {
		return Request{}, err
	}
	if q.Op != OpStatus && q.Op != OpClose {
		return Request{}, fmt.Errorf("session: unknown operation %q", clip(q.Op, 32))
	}
	return q, nil
}

// DecodeResponse parses one response line (also what a starting daemon writes
// to its parent when it is ready).
func DecodeResponse(r io.Reader) (Response, error) {
	var p Response
	if err := decode(r, &p); err != nil {
		return Response{}, err
	}
	return p, nil
}

// Report writes one response line to w.
func Report(w io.Writer, p Response) error { return encode(w, p) }

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func encode(w io.Writer, v any) error {
	b, _ := json.Marshal(v) // a Request or a Response: cannot fail
	if len(b)+1 > MaxMessage {
		return ErrTooLong
	}
	_, err := w.Write(append(b, '\n'))
	return err
}

// checkName refuses a profile name that could leave the directory (or the pipe
// namespace) the endpoint lives in. SocketPath (path_unix.go, path_windows.go)
// is where the session of profile name listens.
func checkName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return fmt.Errorf("session: bad name %q", clip(name, 32))
	}
	return nil
}

// ---- server ----

// Server answers on a Unix socket, or on a named pipe on Windows.
type Server struct {
	l    net.Listener
	path string
	wg   sync.WaitGroup
	once sync.Once

	mu      sync.Mutex
	closing bool
}

// Listen creates the socket. A socket another process answers on is
// ErrAlreadyOpen; one nobody answers on is a leftover and is replaced.
func Listen(path string) (*Server, error) {
	l, err := listenEndpoint(path)
	if err != nil {
		return nil, err
	}
	return &Server{l: l, path: path}, nil
}

// Serve answers connections until Shutdown. It returns nil then.
func (s *Server) Serve(h Handler) error {
	for {
		c, err := s.l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// Add and Wait must not race: once Shutdown has begun, a connection
		// that was accepted just before is dropped.
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			c.Close()
			return nil
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c, h)
		}()
	}
}

// ioTimeout bounds one request: a client that stalls does not hold the server.
const ioTimeout = 5 * time.Second

// closeTimeout bounds the teardown a close request waits for.
var closeTimeout = 2 * time.Minute

func (s *Server) handle(c net.Conn, h Handler) {
	c.SetReadDeadline(time.Now().Add(ioTimeout))
	if authorize(c) != nil {
		encode(c, Response{Error: ErrPeer.Error()})
		return
	}
	q, err := DecodeRequest(c)
	if err != nil {
		encode(c, Response{Error: err.Error()})
		return
	}
	switch q.Op {
	case OpStatus:
		i := h.Status()
		encode(c, Response{OK: true, Info: &i})
	default: // OpClose, DecodeRequest admits no other
		c.SetWriteDeadline(time.Now().Add(closeTimeout))
		if err := h.Close(); err != nil {
			encode(c, Response{Error: clip(err.Error(), 1024)})
			return
		}
		encode(c, Response{OK: true})
	}
}

// Shutdown stops accepting, waits for the requests in flight, and removes the
// socket.
func (s *Server) Shutdown() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		s.l.Close()
		s.wg.Wait()
		removeEndpoint(s.path)
	})
}

// ---- client ----

func call(ctx context.Context, path string, op string, wait time.Duration) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	c, err := dialEndpoint(ctx, path)
	if err != nil {
		return Response{}, ErrNotOpen
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := encode(c, Request{Op: op}); err != nil {
		return Response{}, err
	}
	r, err := DecodeResponse(c)
	if err != nil {
		return Response{}, err
	}
	if !r.OK {
		if r.Error == "" {
			r.Error = "refused"
		}
		return r, errors.New(r.Error)
	}
	return r, nil
}

// Status asks the session at path what it holds; ErrNotOpen when nobody answers.
func Status(ctx context.Context, path string) (Info, error) {
	r, err := call(ctx, path, OpStatus, ioTimeout)
	if err != nil {
		return Info{}, err
	}
	if r.Info == nil {
		return Info{}, errors.New("session: status without info")
	}
	return *r.Info, nil
}

// Close asks the session at path to unmount, commit and close, and waits until it
// has.
func Close(ctx context.Context, path string) error {
	_, err := call(ctx, path, OpClose, closeTimeout)
	return err
}
