package fido2

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"

	authn "github.com/go-authn/fido"
	linuxfido "github.com/go-gnulinux/fido"
	macfido "github.com/go-macos/fido"
)

func cborMarshal(v any) ([]byte, error) { return cbor.Marshal(v) }

// answerKey is a key that answers the handshake, getInfo and
// authenticatorSelection at once, so a touch is instant.
type answerKey struct {
	name string
	// hold, when set, delays the touch until it is closed.
	hold  chan struct{}
	mu    sync.Mutex
	inbox chan []byte
	reasm map[uint32]*authn.Reassembler
}

func newAnswerKey(name string) *answerKey {
	return &answerKey{name: name, inbox: make(chan []byte, 32)}
}

func (a *answerKey) Name() string { return a.name }
func (a *answerKey) Close() error { return nil }
func (a *answerKey) Receive(ctx context.Context) ([]byte, error) {
	select {
	case r := <-a.inbox:
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (a *answerKey) say(ch uint32, cmd byte, data []byte) {
	p, _ := authn.Split(ch, cmd, data)
	for _, r := range p {
		a.inbox <- r
	}
}
func (a *answerKey) Send(report []byte) error {
	ch := binary.BigEndian.Uint32(report[0:4])
	a.mu.Lock()
	if a.reasm == nil {
		a.reasm = map[uint32]*authn.Reassembler{}
	}
	r, ok := a.reasm[ch]
	if !ok {
		r = authn.NewReassembler(ch)
		a.reasm[ch] = r
	}
	msg, done, err := r.Feed(report)
	a.mu.Unlock()
	if err != nil || !done {
		return nil
	}
	const own = 0x0A0B0C0D
	switch msg.Cmd {
	case authn.CmdInit:
		p := make([]byte, 17)
		copy(p, msg.Data[:8])
		binary.BigEndian.PutUint32(p[8:12], own)
		p[12], p[13], p[14], p[15] = 2, 5, 7, 4
		p[16] = byte(authn.CapCBOR)
		a.say(authn.BroadcastChannel, authn.CmdInit, p)
	case authn.CmdCBOR:
		switch msg.Data[0] {
		case authn.CmdGetInfo:
			b, _ := cborMarshal(map[uint64]any{1: []string{"FIDO_2_1"}, 4: map[string]bool{"clientPin": true}})
			a.say(own, authn.CmdCBOR, append([]byte{0}, b...))
		case authn.CmdSelection:
			if a.hold == nil {
				a.say(own, authn.CmdCBOR, []byte{0})
				break
			}
			go func() { // touched only when the test lets go
				<-a.hold
				a.say(own, authn.CmdCBOR, []byte{0})
			}()
		default:
			a.say(own, authn.CmdCBOR, []byte{0x01})
		}
	}
	return nil
}

func (a *answerKey) dev(id string) keyDevice {
	return keyDevice{ID: id, Label: a.name + " at " + id, open: func(ctx context.Context) (*authn.Key, error) {
		return authn.Open(ctx, a)
	}}
}

func withKeys(t *testing.T, devs []keyDevice, err error) {
	t.Helper()
	old := listKeys
	t.Cleanup(func() { listKeys = old })
	listKeys = func() ([]keyDevice, error) { return devs, err }
}

func TestKeysAreListedPerPlatformInAStableOrder(t *testing.T) {
	ol, om, olo, oOM, oOL, og := listKeys, listMac, listLinux, openMacDevice, openLinuxDevice, goos
	t.Cleanup(func() { listKeys, listMac, listLinux, openMacDevice, openLinuxDevice, goos = ol, om, olo, oOM, oOL, og })
	k := newAnswerKey("K")
	opened := ""
	listMac = func() ([]macfido.Device, error) {
		return []macfido.Device{{Path: "iokit:2"}, {Path: "iokit:1"}}, nil
	}
	openMacDevice = func(d macfido.Device) (authn.Transport, error) { opened = d.Path; return k, nil }
	listLinux = func() ([]linuxfido.Device, error) {
		return []linuxfido.Device{{Path: "/dev/hidraw1", Phys: "usb-0000:00:14.0-3/input0"}, {Path: "/dev/hidraw0"}}, nil
	}
	openLinuxDevice = func(d linuxfido.Device) (authn.Transport, error) { opened = d.Path; return k, nil }

	goos = "darwin"
	ds, err := listKeys()
	if err != nil || len(ds) != 2 || ds[0].ID != "iokit:1" || ds[1].ID != "iokit:2" {
		t.Fatalf("%+v %v", ds, err)
	}
	key, err := ds[1].open(ctx)
	if err != nil || opened != "iokit:2" {
		t.Fatalf("%q %v", opened, err)
	}
	key.Close()

	goos = "linux"
	ds, err = listKeys()
	// The port when there is one (it survives another key being plugged in
	// first), the node otherwise.
	if err != nil || len(ds) != 2 || ds[0].ID != "/dev/hidraw0" || ds[1].ID != "usb-0000:00:14.0-3/input0" {
		t.Fatalf("%+v %v", ds, err)
	}
	if key, err = ds[1].open(ctx); err != nil || opened != "/dev/hidraw1" {
		t.Fatalf("%q %v", opened, err)
	}
	key.Close()

	boom := errors.New("boom")
	openLinuxDevice = func(linuxfido.Device) (authn.Transport, error) { return nil, boom }
	openMacDevice = func(macfido.Device) (authn.Transport, error) { return nil, boom }
	if _, err := ds[0].open(ctx); !errors.Is(err, boom) {
		t.Errorf("linux open: %v", err)
	}
	goos = "darwin"
	ds, _ = listKeys()
	if _, err := ds[0].open(ctx); !errors.Is(err, boom) {
		t.Errorf("mac open: %v", err)
	}
	listMac = func() ([]macfido.Device, error) { return nil, boom }
	listLinux = func() ([]linuxfido.Device, error) { return nil, boom }
	for _, os := range []string{"darwin", "linux"} {
		goos = os
		if _, err := listKeys(); !errors.Is(err, boom) {
			t.Errorf("%s: %v", os, err)
		}
	}
	goos = "plan9"
	if _, err := listKeys(); err == nil {
		t.Error("an unsupported system listed keys")
	}
}

func TestOpenTransportWithoutAChoice(t *testing.T) {
	a, b := newAnswerKey("Alpha"), newAnswerKey("Beta")
	var said []string
	c := &config{notice: func(m string) { said = append(said, m) }}
	boom := errors.New("boom")

	withKeys(t, nil, nil)
	if _, _, err := openTransport(ctx, c); !errors.Is(err, ErrNoKey) {
		t.Errorf("none: %v", err)
	}
	withKeys(t, nil, boom)
	if _, _, err := openTransport(ctx, c); !errors.Is(err, boom) {
		t.Errorf("list: %v", err)
	}

	// One key: used, and named before anything is asked of it. No notice sink
	// is fine. (openKey is the default that calls openTransport.)
	withKeys(t, []keyDevice{a.dev("id:a")}, nil)
	if k, _, err := openKey(ctx, &config{}); err != nil {
		t.Fatal(err)
	} else {
		k.Close()
	}
	k, label, err := openTransport(ctx, c)
	if err != nil || label != "Alpha at id:a" || len(said) != 1 || said[0] != "Using security key: Alpha at id:a" {
		t.Fatalf("%q %v %v", label, err, said)
	}
	k.Close()
	if k, _, err = openTransport(ctx, &config{}); err != nil {
		t.Fatal(err)
	}
	k.Close()

	// --device picks the named one whatever the order, and exactly.
	ot := chooseKey
	t.Cleanup(func() { chooseKey = ot })
	chooseKey = func(context.Context, []keyDevice) (*authn.Selected, error) {
		t.Error("a touch was asked although the device was named")
		return nil, boom
	}
	withKeys(t, []keyDevice{a.dev("id:a"), b.dev("id:b")}, nil)
	k, label, err = openTransport(ctx, &config{device: "id:b"})
	if err != nil || label != "Beta at id:b" {
		t.Fatalf("%q %v", label, err)
	}
	k.Close()
	if _, _, err = openTransport(ctx, &config{device: "id:"}); err == nil || !strings.Contains(err.Error(), "id:a, id:b") {
		t.Errorf("a prefix named a key: %v", err)
	}
	bad := keyDevice{ID: "id:c", open: func(context.Context) (*authn.Key, error) { return nil, boom }}
	withKeys(t, []keyDevice{bad}, nil)
	if _, _, err = openTransport(ctx, &config{}); !errors.Is(err, boom) {
		t.Errorf("open: %v", err)
	}
}

func TestSeveralKeysAndNoDeviceMeansTouchToChoose(t *testing.T) {
	a, b := newAnswerKey("Alpha"), newAnswerKey("Beta")
	a.hold = make(chan struct{}) // Alpha is never touched: Beta is the one
	t.Cleanup(func() { close(a.hold) })
	withKeys(t, []keyDevice{a.dev("id:a"), b.dev("id:b")}, nil)
	oc := chooseKey
	t.Cleanup(func() { chooseKey = oc })
	var said []string
	c := &config{notice: func(m string) { said = append(said, m) }}

	// The real Select over answering keys: one of them is chosen, and the person
	// was shown every key first.
	k, label, err := openTransport(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	if label != "Beta at id:b" {
		t.Errorf("the touched key was not the one chosen: %q", label)
	}
	if len(said) != 2 || !strings.Contains(said[0], "2 security keys are attached") || !strings.Contains(said[0], "Alpha at id:a") ||
		!strings.Contains(said[0], "Beta at id:b") || !strings.Contains(said[0], "Touch the key to use") || !strings.HasPrefix(said[1], "Using security key: ") {
		t.Errorf("notices %q", said)
	}

	// Nothing touched: the error, nothing opened.
	chooseKey = func(context.Context, []keyDevice) (*authn.Selected, error) {
		return nil, &authn.SelectError{Cause: context.DeadlineExceeded}
	}
	if _, _, err = openTransport(ctx, c); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("none touched: %v", err)
	}

	// Two keys touched together: refused, never one picked silently.
	chooseKey = func(ctx context.Context, devs []keyDevice) (*authn.Selected, error) {
		k, err := devs[0].open(ctx)
		return &authn.Selected{Label: devs[0].Label, Key: k, AlsoTouched: []string{devs[1].Label}}, err
	}
	if _, _, err = openTransport(ctx, c); err == nil || !strings.Contains(err.Error(), "touched at the same time") {
		t.Errorf("ambiguous: %v", err)
	}
}

func TestADeviceIsPassedThroughOpenAndNamedByLabel(t *testing.T) {
	f := newFake(true)
	withFake(t, f, nil)
	d, err := Open(ctx, pinFn("1"), WithDevice("iokit:123"), WithNotice(func(string) {}))
	if err != nil {
		t.Fatal(err)
	}
	if lastConfig.device != "iokit:123" || lastConfig.notice == nil || d.Label() != "fake key" {
		t.Errorf("config %+v label %q", lastConfig, d.Label())
	}
	// Windows chooses in its own dialog and refuses a device ID.
	sg, sw := goos, winAPI
	t.Cleanup(func() { goos, winAPI = sg, sw })
	goos, winAPI = "windows", goodWin()
	if _, err := Open(ctx, nil, WithDevice("x")); err == nil || !strings.Contains(err.Error(), "does not apply on Windows") {
		t.Errorf("windows with a device: %v", err)
	}
	w, err := Open(ctx, nil)
	if err != nil || !strings.Contains(w.Label(), "Windows") {
		t.Errorf("%v %v", w, err)
	}
}
