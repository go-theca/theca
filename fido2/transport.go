package fido2

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	authn "github.com/go-authn/fido"
	linuxfido "github.com/go-gnulinux/fido"
	macfido "github.com/go-macos/fido"
)

// keyDevice is one attached key, listed without being opened.
type keyDevice struct {
	// ID is what WithDevice takes. Label names the key to a person.
	ID, Label string
	open      func(context.Context) (*authn.Key, error)
}

// selectTimeout is how long the person has to touch the key to use.
var selectTimeout = 30 * time.Second

// The transports' listings and openers, replaced by tests.
var (
	listMac         = macfido.Devices
	openMacDevice   = macfido.OpenDevice
	listLinux       = linuxfido.Devices
	openLinuxDevice = linuxfido.OpenDevice
)

// ErrNoKey is returned when no security key is attached.
var ErrNoKey = errors.New("fido2: no security key is attached")

// listKeys lists the attached keys over the operating system's CTAPHID
// transport, chosen by GOOS (Windows takes another route, see platform.go):
//
//   - macOS: go-macos/fido (IOKit HID); the ID is iokit:<USB location>.
//   - Linux: go-gnulinux/fido (/dev/hidraw*, found by the FIDO usage page
//     0xF1D0 in the report descriptor); the ID is the USB port (HID_PHYS),
//     which stays put when another key is plugged in first, else the node. The
//     node is root-only on a stock system: a udev rule granting the user access
//     (libfido2's 70-u2f.rules) is needed, and the error says so.
//
// Nothing is opened and nothing is touched. Tests replace it.
var listKeys = func() ([]keyDevice, error) {
	var out []keyDevice
	switch goos {
	case "darwin":
		ds, err := listMac()
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			out = append(out, keyDevice{ID: d.Path, Label: d.String(), open: func(ctx context.Context) (*authn.Key, error) {
				t, err := openMacDevice(d)
				if err != nil {
					return nil, err
				}
				return authn.Open(ctx, t)
			}})
		}
	case "linux":
		ds, err := listLinux()
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			id := d.Phys
			if id == "" {
				id = d.Path
			}
			out = append(out, keyDevice{ID: id, Label: d.String(), open: func(ctx context.Context) (*authn.Key, error) {
				t, err := openLinuxDevice(d)
				if err != nil {
					return nil, err
				}
				return authn.Open(ctx, t)
			}})
		}
	default:
		return nil, fmt.Errorf("fido2: no CTAP transport for %s", goos)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// chooseKey asks every key for a touch and returns the one touched; tests
// replace it.
var chooseKey = func(ctx context.Context, devs []keyDevice) (*authn.Selected, error) {
	cands := make([]authn.Candidate, len(devs))
	for i, d := range devs {
		cands[i] = authn.Candidate{Label: d.Label, Open: d.open}
	}
	return authn.Select(ctx, cands)
}

// openTransport chooses a key and opens it, saying which one it is.
//
// With WithDevice, that key, matched exactly. With one key attached, that key.
// With several and no device, the person touches the one to use
// (authenticatorSelection, CTAP 2.1 6.9): enrolling a credential or opening a
// container on "the first" would act on a key nobody chose. Two keys touched
// together is refused. The key is named through the notice function BEFORE
// anything is asked of it.
func openTransport(ctx context.Context, c *config) (key, string, error) {
	devs, err := listKeys()
	if err != nil {
		return nil, "", err
	}
	if len(devs) == 0 {
		return nil, "", ErrNoKey
	}
	say := func(m string) {
		if c.notice != nil {
			c.notice(m)
		}
	}
	if c.device != "" || len(devs) == 1 {
		d := devs[0]
		if c.device != "" {
			found := false
			for _, x := range devs {
				if x.ID == c.device {
					d, found = x, true
				}
			}
			if !found {
				var ids []string
				for _, x := range devs {
					ids = append(ids, x.ID)
				}
				return nil, "", fmt.Errorf("fido2: no attached key has the id %q (attached: %s); `fido list` shows them", c.device, strings.Join(ids, ", "))
			}
		}
		k, err := d.open(ctx)
		if err != nil {
			return nil, "", err
		}
		say("Using security key: " + d.Label)
		return k, d.Label, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d security keys are attached:", len(devs))
	for _, d := range devs {
		b.WriteString("\n  " + d.Label)
	}
	fmt.Fprintf(&b, "\nTouch the key to use (%s), or pass --device ID.", selectTimeout)
	say(b.String())
	sctx, stop := context.WithTimeout(ctx, selectTimeout)
	defer stop()
	sel, err := chooseKey(sctx, devs)
	if err != nil {
		return nil, "", err
	}
	if len(sel.AlsoTouched) > 0 {
		sel.Key.Close()
		return nil, "", fmt.Errorf("fido2: %s and %s were touched at the same time; touch ONE key, or pass --device ID",
			sel.Label, strings.Join(sel.AlsoTouched, ", "))
	}
	say("Using security key: " + sel.Label)
	return sel.Key, sel.Label, nil
}
