package lockwatch

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	mySession    = dbus.ObjectPath("/org/freedesktop/login1/session/_31")
	otherSession = dbus.ObjectPath("/org/freedesktop/login1/session/_3999")
	logindOwner  = ":1.7"
)

func TestReason(t *testing.T) {
	from := source{sender: logindOwner, session: mySession}
	v := func(b bool) []any { return []any{b} }
	props := func(iface string, m map[string]dbus.Variant) []any { return []any{iface, m, []string{}} }
	locked := props(sessionIf, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)})
	for _, tc := range []struct {
		s    dbus.Signal
		want string
	}{
		{dbus.Signal{Name: managerIf + ".PrepareForSleep", Body: v(true)}, "sleep"},
		{dbus.Signal{Name: managerIf + ".PrepareForSleep", Body: v(false)}, ""},
		{dbus.Signal{Name: managerIf + ".PrepareForSleep"}, ""},
		{dbus.Signal{Name: managerIf + ".PrepareForShutdown", Body: v(true)}, "shutdown"},
		{dbus.Signal{Name: managerIf + ".PrepareForShutdown", Body: v(false)}, ""},
		{dbus.Signal{Name: sessionIf + ".Lock"}, "lock"},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: locked}, "lock"},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props(sessionIf, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(false)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props(sessionIf, map[string]dbus.Variant{"Other": dbus.MakeVariant(true)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: props("other.Iface", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)})}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged", Body: []any{sessionIf, "not a map"}}, ""},
		{dbus.Signal{Name: propsIf + ".PropertiesChanged"}, ""},
		{dbus.Signal{Name: "x.Y"}, ""},
	} {
		tc.s.Sender = logindOwner
		tc.s.Path = mySession
		if tc.s.Name == managerIf+".PrepareForSleep" || tc.s.Name == managerIf+".PrepareForShutdown" {
			tc.s.Path = loginPath
		}
		if got := reason(&tc.s, from); got != tc.want {
			t.Errorf("%s %v: %q want %q", tc.s.Name, tc.s.Body, got, tc.want)
		}
	}
}

// A signal that does not come from logind, or that is about another session,
// closes nothing (audit L2).
func TestReasonIgnoresSenderAndSession(t *testing.T) {
	from := source{sender: logindOwner, session: mySession}
	locked := []any{sessionIf, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}}
	for _, tc := range []dbus.Signal{
		{Sender: ":1.999", Path: mySession, Name: sessionIf + ".Lock"},
		{Sender: logindOwner, Path: otherSession, Name: sessionIf + ".Lock"},
		{Sender: ":1.999", Path: mySession, Name: propsIf + ".PropertiesChanged", Body: locked},
		{Sender: logindOwner, Path: otherSession, Name: propsIf + ".PropertiesChanged", Body: locked},
		{Sender: ":1.999", Path: loginPath, Name: managerIf + ".PrepareForSleep", Body: []any{true}},
		{Sender: logindOwner, Path: "/x", Name: managerIf + ".PrepareForSleep", Body: []any{true}},
		{Sender: ":1.999", Path: loginPath, Name: managerIf + ".PrepareForShutdown", Body: []any{true}},
		{Sender: logindOwner, Path: "/x", Name: managerIf + ".PrepareForShutdown", Body: []any{true}},
	} {
		if r := reason(&tc, from); r != "" {
			t.Errorf("%s from %s about %s: reason %q", tc.Name, tc.Sender, tc.Path, r)
		}
	}
}

// Every match names logind as the sender and a path.
func TestMatchesNameTheSender(t *testing.T) {
	want := dbus.WithMatchSender(logind)
	for i, m := range matches(mySession) {
		found := false
		for _, o := range m {
			if o == want {
				found = true
			}
		}
		if !found {
			t.Errorf("match %d does not restrict the sender to %s", i, logind)
		}
	}
}

// fakeObject answers the bus calls the watcher makes.
type fakeObject struct {
	dbus.BusObject
	conn *fakeBus
	dest string
	path dbus.ObjectPath
}

func (o fakeObject) Call(method string, _ dbus.Flags, args ...any) *dbus.Call {
	reply := func(body any, err error) *dbus.Call {
		c := &dbus.Call{Err: err}
		if err == nil {
			c.Body = []any{body}
		}
		return c
	}
	switch method {
	case busName + ".GetNameOwner":
		return reply(o.conn.owner, o.conn.ownerErr)
	case managerIf + ".GetSessionByPID":
		o.conn.pidAsked = args[0].(uint32)
		return reply(o.conn.byPID, o.conn.byPIDErr)
	case managerIf + ".GetSession":
		o.conn.idAsked = args[0].(string)
		return reply(o.conn.byID, o.conn.byIDErr)
	}
	return &dbus.Call{Err: errors.New("unexpected " + method)}
}

func (o fakeObject) GetProperty(name string) (dbus.Variant, error) {
	o.conn.propAsked = o.path
	if name != sessionIf+".LockedHint" || o.conn.hintErr != nil {
		return dbus.Variant{}, errors.New("no property")
	}
	return dbus.MakeVariant(o.conn.hint), nil
}

type fakeBus struct {
	ch       chan<- *dbus.Signal
	matchErr error
	matches  int
	removed  bool
	closed   bool

	owner                       string
	byPID, byID                 dbus.ObjectPath
	ownerErr, byPIDErr, byIDErr error
	hint                        bool
	hintErr                     error
	pidAsked                    uint32
	idAsked                     string
	propAsked                   dbus.ObjectPath
}

func newFakeBus() *fakeBus {
	return &fakeBus{owner: logindOwner, byPID: mySession}
}

func (b *fakeBus) AddMatchSignalContext(_ context.Context, _ ...dbus.MatchOption) error {
	b.matches++
	return b.matchErr
}
func (b *fakeBus) Signal(ch chan<- *dbus.Signal)    { b.ch = ch }
func (b *fakeBus) RemoveSignal(chan<- *dbus.Signal) { b.removed = true }
func (b *fakeBus) Close() error                     { b.closed = true; return nil }
func (b *fakeBus) Object(dest string, path dbus.ObjectPath) dbus.BusObject {
	return fakeObject{conn: b, dest: dest, path: path}
}

func open(b *fakeBus) func() (busConn, error) { return func() (busConn, error) { return b, nil } }

func TestWatchBus(t *testing.T) {
	b := newFakeBus()
	out, err := watchBus(context.Background(), open(b))
	if err != nil || b.matches != len(matches(mySession)) {
		t.Fatal(err, b.matches)
	}
	if b.propAsked != mySession {
		t.Fatalf("LockedHint read on %q, not the own session", b.propAsked)
	}
	b.ch <- &dbus.Signal{Name: "irrelevant.Signal", Sender: logindOwner}
	b.ch <- &dbus.Signal{Name: sessionIf + ".Lock", Sender: ":1.999", Path: mySession}
	b.ch <- &dbus.Signal{Name: sessionIf + ".Lock", Sender: logindOwner, Path: otherSession}
	b.ch <- &dbus.Signal{Name: sessionIf + ".Lock", Sender: logindOwner, Path: mySession}
	if r, ok := recv(t, out); !ok || r != "lock" {
		t.Fatal(r, ok)
	}
	if _, ok := recv(t, out); ok {
		t.Fatal("channel not closed")
	}
	if !b.removed || !b.closed {
		t.Fatal("connection not released")
	}
}

// A session already locked when the watch starts is gone at once (audit L3).
func TestWatchBusAlreadyLocked(t *testing.T) {
	b := newFakeBus()
	b.hint = true
	out, err := watchBus(context.Background(), open(b))
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := recv(t, out); !ok || r != "lock" {
		t.Fatal(r, ok)
	}
	if _, ok := recv(t, out); ok {
		t.Fatal("channel not closed")
	}
	if !b.removed || !b.closed {
		t.Fatal("connection not released")
	}
	// A property that cannot be read is not a lock.
	b = newFakeBus()
	b.hint, b.hintErr = true, errors.New("denied")
	if _, err := watchBus(context.Background(), open(b)); err != nil {
		t.Fatal(err)
	}
}

func TestWatchBusEnds(t *testing.T) {
	b := newFakeBus()
	ctx, cancel := context.WithCancel(context.Background())
	out, _ := watchBus(ctx, open(b))
	cancel()
	if _, ok := recv(t, out); ok {
		t.Fatal("reported after cancel")
	}
	// The bus closing its signal channel ends the watch too.
	b2 := newFakeBus()
	out, _ = watchBus(context.Background(), open(b2))
	close(b2.ch)
	if _, ok := recv(t, out); ok {
		t.Fatal("reported on a closed bus")
	}
}

func TestWatchBusErrors(t *testing.T) {
	boom := errors.New("no bus")
	if _, err := watchBus(context.Background(), func() (busConn, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	b := newFakeBus()
	b.matchErr = boom
	if _, err := watchBus(context.Background(), open(b)); !errors.Is(err, boom) || !b.removed || !b.closed {
		t.Fatal(err, b)
	}
	// logind not on the bus, or no session: refused, connection closed.
	b = newFakeBus()
	b.ownerErr = boom
	if _, err := watchBus(context.Background(), open(b)); !errors.Is(err, boom) || !b.closed {
		t.Fatal(err, b)
	}
	b = newFakeBus()
	b.byPIDErr = boom
	t.Setenv("XDG_SESSION_ID", "")
	if _, err := watchBus(context.Background(), open(b)); !errors.Is(err, boom) || !b.closed {
		t.Fatal(err, b)
	}
}

func TestOwnSession(t *testing.T) {
	boom := errors.New("no such process")
	savedPID, savedEnv := selfPID, getenv
	t.Cleanup(func() { selfPID, getenv = savedPID, savedEnv })
	selfPID = func() int { return 4242 }
	getenv = func(k string) string {
		if k == "XDG_SESSION_ID" {
			return "c2"
		}
		return ""
	}

	b := newFakeBus()
	if p, err := ownSession(b); err != nil || p != mySession || b.pidAsked != 4242 {
		t.Fatal(p, err, b.pidAsked)
	}
	// logind knows no session for the pid: the environment names it.
	b = newFakeBus()
	b.byPIDErr, b.byID = boom, otherSession
	if p, err := ownSession(b); err != nil || p != otherSession || b.idAsked != "c2" {
		t.Fatal(p, err, b.idAsked)
	}
	b.byIDErr = boom
	if _, err := ownSession(b); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	getenv = func(string) string { return "" }
	if _, err := ownSession(b); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestAsBus(t *testing.T) {
	boom := errors.New("x")
	if c, err := asBus(nil, boom); c != nil || !errors.Is(err, boom) {
		t.Fatal(c, err)
	}
	if c, err := asBus(&dbus.Conn{}, nil); c == nil || err != nil {
		t.Fatal(c, err)
	}
}
