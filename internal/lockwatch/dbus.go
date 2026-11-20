package lockwatch

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// busConn is what the logind watcher needs of a bus connection.
type busConn interface {
	AddMatchSignalContext(ctx context.Context, options ...dbus.MatchOption) error
	Signal(ch chan<- *dbus.Signal)
	RemoveSignal(ch chan<- *dbus.Signal)
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
	loginPath = "/org/freedesktop/login1"
	managerIf = "org.freedesktop.login1.Manager"
	sessionIf = "org.freedesktop.login1.Session"
	propsIf   = "org.freedesktop.DBus.Properties"
)

// matches are the signals that mean "gone".
var matches = [][]dbus.MatchOption{
	{dbus.WithMatchInterface(managerIf), dbus.WithMatchMember("PrepareForSleep")},
	{dbus.WithMatchInterface(managerIf), dbus.WithMatchMember("PrepareForShutdown")},
	{dbus.WithMatchInterface(sessionIf), dbus.WithMatchMember("Lock")},
	{dbus.WithMatchInterface(propsIf), dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchPathNamespace(loginPath + "/session")},
}

// reason says what a signal means, "" when nothing.
func reason(s *dbus.Signal) string {
	switch s.Name {
	case managerIf + ".PrepareForSleep":
		if len(s.Body) == 1 && s.Body[0] == true {
			return "sleep"
		}
	case managerIf + ".PrepareForShutdown":
		if len(s.Body) == 1 && s.Body[0] == true {
			return "shutdown"
		}
	case sessionIf + ".Lock":
		return "lock"
	case propsIf + ".PropertiesChanged":
		if len(s.Body) >= 2 && s.Body[0] == sessionIf {
			if m, ok := s.Body[1].(map[string]dbus.Variant); ok {
				if v, ok := m["LockedHint"]; ok && v.Value() == true {
					return "lock"
				}
			}
		}
	}
	return ""
}

// watchBus subscribes on a bus and forwards the first reason that arrives.
func watchBus(ctx context.Context, open func() (busConn, error)) (<-chan string, error) {
	conn, err := open()
	if err != nil {
		return nil, err
	}
	sigs := make(chan *dbus.Signal, 16)
	conn.Signal(sigs)
	for _, m := range matches {
		if err := conn.AddMatchSignalContext(ctx, m...); err != nil {
			conn.RemoveSignal(sigs)
			conn.Close()
			return nil, err
		}
	}
	out := make(chan string, 1)
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
				if r := reason(s); r != "" {
					out <- r
					return
				}
			}
		}
	}()
	return out, nil
}
