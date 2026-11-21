package lockwatch

import (
	"context"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// busConn is what the logind watcher needs of a bus connection.
type busConn interface {
	AddMatchSignalContext(ctx context.Context, options ...dbus.MatchOption) error
	Signal(ch chan<- *dbus.Signal)
	RemoveSignal(ch chan<- *dbus.Signal)
	Object(dest string, path dbus.ObjectPath) dbus.BusObject
	Close() error
}

// asBus keeps a nil *dbus.Conn from becoming a non-nil interface.
func asBus(c *dbus.Conn, err error) (busConn, error) {
	if err != nil {
		return nil, err
	}
	return c, nil
}

const (
	logind    = "org.freedesktop.login1"
	loginPath = "/org/freedesktop/login1"
	managerIf = "org.freedesktop.login1.Manager"
	sessionIf = "org.freedesktop.login1.Session"
	propsIf   = "org.freedesktop.DBus.Properties"
	busName   = "org.freedesktop.DBus"
	busPath   = "/org/freedesktop/DBus"
)

// Replaced by tests: the process id and the environment that name this
// process's own login session.
var (
	selfPID = os.Getpid
	getenv  = os.Getenv
)

// matches are the signals that mean "gone": only logind's, and the session
// ones only for the session this process belongs to.
func matches(session dbus.ObjectPath) [][]dbus.MatchOption {
	from := dbus.WithMatchSender(logind)
	return [][]dbus.MatchOption{
		{from, dbus.WithMatchObjectPath(loginPath), dbus.WithMatchInterface(managerIf), dbus.WithMatchMember("PrepareForSleep")},
		{from, dbus.WithMatchObjectPath(loginPath), dbus.WithMatchInterface(managerIf), dbus.WithMatchMember("PrepareForShutdown")},
		{from, dbus.WithMatchObjectPath(session), dbus.WithMatchInterface(sessionIf), dbus.WithMatchMember("Lock")},
		{from, dbus.WithMatchObjectPath(session), dbus.WithMatchInterface(propsIf), dbus.WithMatchMember("PropertiesChanged")},
	}
}

// source is whom a signal is believed from: logind's unique bus name (a
// well-known name cannot be read off a signal) and this process's session.
type source struct {
	sender  string
	session dbus.ObjectPath
}

// ownSession finds the login session this process belongs to: logind's answer
// for its pid, else the session XDG_SESSION_ID names.
func ownSession(conn busConn) (dbus.ObjectPath, error) {
	mgr := conn.Object(logind, loginPath)
	var p dbus.ObjectPath
	err := mgr.Call(managerIf+".GetSessionByPID", 0, uint32(selfPID())).Store(&p)
	if err == nil {
		return p, nil
	}
	id := getenv("XDG_SESSION_ID")
	if id == "" {
		return "", fmt.Errorf("lockwatch: this process belongs to no logind session: %w", err)
	}
	if err2 := mgr.Call(managerIf+".GetSession", 0, id).Store(&p); err2 != nil {
		return "", fmt.Errorf("lockwatch: session %q: %w", id, err2)
	}
	return p, nil
}

// reason says what a signal means, "" when nothing, or when it did not come
// from logind or concerns another session.
func reason(s *dbus.Signal, from source) string {
	if s.Sender != from.sender {
		return ""
	}
	switch s.Name {
	case managerIf + ".PrepareForSleep":
		if s.Path == loginPath && len(s.Body) == 1 && s.Body[0] == true {
			return "sleep"
		}
	case managerIf + ".PrepareForShutdown":
		if s.Path == loginPath && len(s.Body) == 1 && s.Body[0] == true {
			return "shutdown"
		}
	case sessionIf + ".Lock":
		if s.Path == from.session {
			return "lock"
		}
	case propsIf + ".PropertiesChanged":
		if s.Path == from.session && len(s.Body) >= 2 && s.Body[0] == sessionIf {
			if m, ok := s.Body[1].(map[string]dbus.Variant); ok {
				if v, ok := m["LockedHint"]; ok && v.Value() == true {
					return "lock"
				}
			}
		}
	}
	return ""
}

// lockedNow reads the session's LockedHint: a session already locked when the
// watch starts is gone at once.
func lockedNow(conn busConn, session dbus.ObjectPath) bool {
	v, err := conn.Object(logind, session).GetProperty(sessionIf + ".LockedHint")
	return err == nil && v.Value() == true
}

// watchBus subscribes on a bus and forwards the first reason that arrives. It
// fails when logind or this process's session cannot be identified: the caller
// would otherwise believe it is protected.
func watchBus(ctx context.Context, open func() (busConn, error)) (<-chan string, error) {
	conn, err := open()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (<-chan string, error) {
		conn.Close()
		return nil, err
	}
	var owner string
	if err := conn.Object(busName, busPath).Call(busName+".GetNameOwner", 0, logind).Store(&owner); err != nil {
		return fail(fmt.Errorf("lockwatch: who is %s: %w", logind, err))
	}
	session, err := ownSession(conn)
	if err != nil {
		return fail(err)
	}
	from := source{sender: owner, session: session}
	sigs := make(chan *dbus.Signal, 16)
	conn.Signal(sigs)
	for _, m := range matches(session) {
		if err := conn.AddMatchSignalContext(ctx, m...); err != nil {
			conn.RemoveSignal(sigs)
			return fail(err)
		}
	}
	out := make(chan string, 1)
	// Read after the matches are in place: a lock between the two is heard.
	if lockedNow(conn, session) {
		out <- "lock"
		conn.RemoveSignal(sigs)
		conn.Close()
		close(out)
		return out, nil
	}
	go func() {
		defer close(out)
		defer conn.Close()
		defer conn.RemoveSignal(sigs)
		for {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-sigs:
				if !ok {
					return
				}
				if r := reason(s, from); r != "" {
					out <- r
					return
				}
			}
		}
	}()
	return out, nil
}
