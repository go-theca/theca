package fido2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/go-mswin/webauthn"

	"github.com/go-theca/theca"
)

// fakeWin plays webauthn.dll with one credential: it answers
// HMAC-SHA-256(secret, salt) like a key would, and records the requests.
type fakeWin struct {
	version     uint32
	regErr      error
	assertErr   error
	reg         webauthn.Registration
	regReq      webauthn.RegisterRequest
	assertReqs  []webauthn.Request
	noOutput    bool
	secret      []byte
	partialOut  bool
	registerNil bool
}

func (f *fakeWin) APIVersion() uint32 { return f.version }

func (f *fakeWin) Register(_ context.Context, r webauthn.RegisterRequest) (*webauthn.Registration, error) {
	f.regReq = r
	if f.regErr != nil {
		return nil, f.regErr
	}
	reg := f.reg
	return &reg, nil
}

func (f *fakeWin) Assert(_ context.Context, r webauthn.Request) (*webauthn.Assertion, error) {
	f.assertReqs = append(f.assertReqs, r)
	if f.assertErr != nil {
		return nil, f.assertErr
	}
	a := &webauthn.Assertion{}
	if f.noOutput {
		return a, nil
	}
	for i, s := range r.HMACSalts {
		if f.partialOut && i == 1 {
			break
		}
		h := hmac.New(sha256.New, f.secret)
		h.Write(s[:])
		a.HMACSecret = append(a.HMACSecret, h.Sum(nil))
	}
	return a, nil
}

func goodWin() *fakeWin {
	return &fakeWin{
		version: 9, secret: bytes.Repeat([]byte{5}, 32),
		reg: webauthn.Registration{
			CredentialID: []byte("cred"), Discoverable: true, DiscoverableKnown: true,
			HMACSecret: true, CredProtect: 3,
		},
	}
}

func withWindows(t *testing.T, w *fakeWin) {
	t.Helper()
	sg, sw := goos, winAPI
	t.Cleanup(func() { goos, winAPI = sg, sw })
	goos, winAPI = "windows", w
}

func TestWindowsEnrollThenDeriveAgree(t *testing.T) {
	w := goodWin()
	withWindows(t, w)
	pinCalled := false
	d, err := Open(ctx, func() (string, error) { pinCalled = true; return "x", nil })
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	salts := [][32]byte{{1}, {2}}
	en, err := d.Enroll(ctx, salts)
	if err != nil || len(en) != 2 {
		t.Fatalf("enroll: %v %v", en, err)
	}
	r := w.regReq
	if r.RPID != RPID || !r.Discoverable || !r.HMACSecret || r.CredProtect != 3 ||
		r.Attachment != webauthn.CrossPlatform || r.Verification != webauthn.VerificationRequired || len(r.User.ID) != 16 {
		t.Fatalf("registration request = %+v", r)
	}
	if got := w.assertReqs[0]; len(got.Allow) != 1 || string(got.Allow[0].ID) != "cred" {
		t.Fatalf("the enrolment assertion did not name the new credential: %+v", got)
	}
	dv, err := d.Derive(ctx, salts)
	if err != nil || len(dv) != 1 || len(dv[0]) != 2 {
		t.Fatalf("derive: %v %v", dv, err)
	}
	for i := range en {
		if !bytes.Equal(en[i], dv[0][i]) {
			t.Errorf("output %d differs between enrol and derive", i)
		}
	}
	if len(w.assertReqs[1].Allow) != 0 {
		t.Error("derive must ask for a discoverable credential, naming none")
	}
	if pinCalled {
		t.Error("the PIN function was called: Windows owns the PIN")
	}
}

func TestWindowsRefusals(t *testing.T) {
	cases := map[string]struct {
		mut  func(*fakeWin)
		want error
	}{
		"old windows":            {func(w *fakeWin) { w.version = 5 }, ErrUnsuitable},
		"not discoverable":       {func(w *fakeWin) { w.reg.Discoverable = false }, ErrUnsuitable},
		"no hmac-secret":         {func(w *fakeWin) { w.reg.HMACSecret = false }, ErrUnsuitable},
		"credProtect not 3":      {func(w *fakeWin) { w.reg.CredProtect = 2 }, ErrUnsuitable},
		"no output at enrolment": {func(w *fakeWin) { w.noOutput = true }, ErrUnsuitable},
		"cancelled":              {func(w *fakeWin) { w.regErr = webauthn.ErrCancelled }, ErrNotTouched},
		"cancelled by assert":    {func(w *fakeWin) { w.assertErr = webauthn.ErrCancelled }, ErrNotTouched},
		"no device":              {func(w *fakeWin) { w.assertErr = &webauthn.Error{HResult: 0x80090011} }, theca.ErrNoCredential},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := goodWin()
			c.mut(w)
			withWindows(t, w)
			d, err := Open(ctx, nil)
			if err == nil {
				defer d.Close()
				_, err = d.Enroll(ctx, [][32]byte{{1}})
				if name == "no device" {
					_, err = d.Derive(ctx, [][32]byte{{1}})
				}
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestWindowsDeriveWithoutOutputIsNoCredential(t *testing.T) {
	w := goodWin()
	w.noOutput = true
	withWindows(t, w)
	d, _ := Open(ctx, nil)
	if _, err := d.Derive(ctx, [][32]byte{{1}}); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatalf("err = %v", err)
	}
	w.noOutput, w.partialOut = false, true
	if _, err := d.Derive(ctx, [][32]byte{{1}, {2}}); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatalf("a short answer was used: %v", err)
	}
	if _, err := d.Derive(ctx, nil); err == nil {
		t.Error("no salts accepted")
	}
	if _, err := d.Enroll(ctx, make([][32]byte, 3)); err == nil {
		t.Error("three salts accepted")
	}
}

// The real passthrough is reached with empty requests, which every build
// refuses (the stub says unsupported, Windows' own check says the request is
// incomplete) before any dialog could appear.
func TestTheRealPlatformIsReachedWithoutADialog(t *testing.T) {
	var p realPlatform
	if _, err := p.Register(ctx, webauthn.RegisterRequest{}); err == nil {
		t.Error("an empty registration was accepted")
	}
	if _, err := p.Assert(ctx, webauthn.Request{}); err == nil {
		t.Error("an empty assertion was accepted")
	}
	_ = p.APIVersion()
}

func TestMapPlatformErrPassesOthersThrough(t *testing.T) {
	boom := errors.New("boom")
	if got := mapPlatformErr(boom); got != boom {
		t.Errorf("got %v", got)
	}
	cancelled := &webauthn.Error{HResult: 0x800704c7} // ERROR_CANCELLED as an HRESULT
	if got := mapPlatformErr(cancelled); !errors.Is(got, ErrNotTouched) {
		t.Errorf("a cancelled Error was not mapped: %v", got)
	}
}
