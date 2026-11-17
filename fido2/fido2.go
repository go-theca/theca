// Package fido2 is Theca's FIDO2 factor on a real authenticator: it
// implements theca.FIDO2 over go-authn/fido (CTAP 2.1) and, on macOS, the
// go-macos/fido transport.
//
// Decision H2 (revised, DESIGN 19 I21): one DISCOVERABLE credential per
// enrolment, relying party "theca", credProtect 3, hmac-secret; nothing about
// it is stored in the container. Unlock walks every Theca credential on the
// key with ONE verified request (measured on a YubiKey 5.7.4: the next
// assertions carry their hmac-secret outputs). A credential whose answer has
// no output is skipped, never used as a key.
//
// User verification: the key's own (a fingerprint) when it declares "uv",
// otherwise its PIN, which the caller supplies through a function so that it
// is never an argument or an environment variable.
package fido2

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"

	authn "github.com/go-authn/fido"

	"github.com/go-theca/theca"
)

// RPID is the relying party of every Theca credential: a constant of the
// format, not a domain, so no web origin can ask for it (HARDWARE-KEYS 8.2).
const RPID = "theca"

// Errors.
var (
	// ErrUnsuitable: the authenticator lacks something Theca requires.
	ErrUnsuitable = errors.New("fido2: this authenticator cannot hold a Theca key")
	// ErrNotTouched: nobody touched the key in time.
	ErrNotTouched = errors.New("fido2: the key was not touched in time")
	// ErrPINLocked: the key will not take a PIN now.
	ErrPINLocked = errors.New("fido2: the key's PIN is blocked or needs the key to be unplugged")
)

// key is the part of *authn.Key this package uses; tests replace it.
type key interface {
	GetInfo(context.Context) (authn.Info, error)
	PINRetries(context.Context) (authn.Retries, error)
	PINToken(context.Context, string, authn.PINProtocol, authn.Permissions, string) (authn.Token, error)
	UVToken(context.Context, authn.PINProtocol, authn.Permissions, string) (authn.Token, error)
	MakeCredential(context.Context, authn.MakeCredentialRequest) (*authn.Attestation, error)
	GetAssertion(context.Context, authn.GetAssertionRequest) (*authn.Assertion, error)
	GetAssertions(context.Context, authn.GetAssertionRequest, int) ([]*authn.Assertion, error)
	Close() error
}

// Device is one authenticator, ready to enrol or derive.
type Device struct {
	k     key
	pin   func() (string, error)
	proto authn.PINProtocol
	uv    bool      // built-in user verification (a fingerprint)
	win   *platform // Windows: webauthn.dll does CTAP, the PIN and the UI; k is nil
}

var _ theca.FIDO2 = (*Device)(nil)

// openKey opens the attached authenticator; tests replace it.
var openKey = func(ctx context.Context) (key, error) { return openTransport(ctx) }

// goos and winAPI are seams: tests choose the operating system and fake
// webauthn.dll.
var (
	goos               = runtime.GOOS
	winAPI platformAPI = realPlatform{}
)

// Open finds the attached key and checks that it can hold a Theca credential:
// hmac-secret, credProtect, discoverable credentials, and a way to verify
// the person (its own, or a PIN, which pin returns when asked).
func Open(ctx context.Context, pin func() (string, error)) (*Device, error) {
	if goos == "windows" {
		// Windows will not let an unelevated process open the key (1903+); it
		// does the PIN and the dialog itself, so pin is not used.
		w, err := openPlatform(winAPI)
		if err != nil {
			return nil, err
		}
		return &Device{win: w}, nil
	}
	k, err := openKey(ctx)
	if err != nil {
		return nil, err
	}
	d, err := newDevice(ctx, k, pin)
	if err != nil {
		k.Close()
		return nil, err
	}
	return d, nil
}

func newDevice(ctx context.Context, k key, pin func() (string, error)) (*Device, error) {
	info, err := k.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	for _, ext := range []string{"hmac-secret", "credProtect"} {
		if !contains(info.Extensions, ext) {
			return nil, fmt.Errorf("%w: no %s extension", ErrUnsuitable, ext)
		}
	}
	if !info.Has("rk") || !info.Has("pinUvAuthToken") {
		return nil, fmt.Errorf("%w: no discoverable credentials or no pinUvAuthToken", ErrUnsuitable)
	}
	d := &Device{k: k, pin: pin, proto: authn.PINProtocolOne, uv: info.Has("uv")}
	for _, p := range info.PINProtocols {
		if p == uint(authn.PINProtocolTwo) {
			d.proto = authn.PINProtocolTwo
		}
	}
	if !d.uv && (!info.Has("clientPin") || pin == nil) {
		return nil, fmt.Errorf("%w: it has no built-in verification, and no PIN is set or none can be asked", ErrUnsuitable)
	}
	return d, nil
}

// Close releases the authenticator.
func (d *Device) Close() error {
	if d.win != nil {
		return nil
	}
	return d.k.Close()
}

// token verifies the person for one permission.
func (d *Device) token(ctx context.Context, perm authn.Permissions) (authn.Token, error) {
	if d.uv {
		tok, err := d.k.UVToken(ctx, d.proto, perm, RPID)
		return tok, mapErr(err)
	}
	r, err := d.k.PINRetries(ctx)
	if err != nil {
		return authn.Token{}, mapErr(err)
	}
	if r.PIN == 0 || r.PowerCycle {
		return authn.Token{}, fmt.Errorf("%w (%d tries left, power cycle needed: %v)", ErrPINLocked, r.PIN, r.PowerCycle)
	}
	pin, err := d.pin()
	if err != nil {
		return authn.Token{}, err
	}
	tok, err := d.k.PINToken(ctx, pin, d.proto, perm, RPID)
	if err != nil {
		return authn.Token{}, fmt.Errorf("%w (%d tries were left before this one)", mapErr(err), r.PIN)
	}
	return tok, nil
}

// hmacInput builds the request's hmac-secret input for one or two salts.
func (d *Device) hmacInput(salts [][32]byte) (*authn.HMACSecret, error) {
	if len(salts) == 0 || len(salts) > theca.MaxFIDO2Salts {
		return nil, fmt.Errorf("fido2: %d salts, want 1 or %d", len(salts), theca.MaxFIDO2Salts)
	}
	h := &authn.HMACSecret{Protocol: d.proto, Salt1: salts[0][:], RequireUV: true}
	if len(salts) == 2 {
		h.Salt2 = salts[1][:]
	}
	return h, nil
}

// outputs copies an assertion's hmac-secret outputs, one per salt.
func outputs(o *authn.HMACSecretOutput, n int) [][]byte {
	out := [][]byte{append([]byte(nil), o.First...)}
	if n == 2 {
		out = append(out, append([]byte(nil), o.Second...))
	}
	return out
}

// random returns n fresh bytes. crypto/rand.Read does not return an error
// since Go 1.24 (it aborts the program instead), so none is handled.
func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// Enroll makes a new discoverable credential and returns its outputs for the
// salts: two touches, one to register and one to assert, because the
// YubiKey 5.7 does not offer hmac-secret-mc (HARDWARE-KEYS 5.1).
func (d *Device) Enroll(ctx context.Context, salts [][32]byte) ([][]byte, error) {
	if d.win != nil {
		return d.win.enroll(ctx, salts)
	}
	h, err := d.hmacInput(salts)
	if err != nil {
		return nil, err
	}
	// Theca checks no signature, only the hmac-secret output, so the client
	// data hash only has to be fresh; and the user handle is random: nothing
	// that names the person or the container.
	cdh, uid := random(32), random(16)
	tok, err := d.token(ctx, authn.PermMakeCredential)
	if err != nil {
		return nil, err
	}
	att, err := d.k.MakeCredential(ctx, authn.MakeCredentialRequest{
		ClientDataHash: cdh,
		RP:             authn.RelyingParty{ID: RPID, Name: "Theca"},
		User:           authn.User{ID: uid},
		Options:        map[string]bool{"rk": true},
		Token:          tok,
		Extensions:     authn.Extensions{HMACSecret: true, CredProtect: authn.CredProtectRequired},
	})
	if err != nil {
		return nil, mapErr(err)
	}
	if !att.Extensions.HMACSecret || att.Extensions.CredProtect != authn.CredProtectRequired {
		return nil, fmt.Errorf("%w: the credential was made without hmac-secret or credProtect 3", ErrUnsuitable)
	}
	tok, err = d.token(ctx, authn.PermGetAssertion)
	if err != nil {
		return nil, err
	}
	a, err := d.k.GetAssertion(ctx, authn.GetAssertionRequest{
		RPID: RPID, ClientDataHash: cdh, Token: tok, HMACSecret: h,
		Allow: []authn.Credential{{Type: "public-key", ID: att.Parsed.CredentialID}},
	})
	if err != nil {
		return nil, mapErr(err)
	}
	if a.HMACSecret == nil {
		return nil, fmt.Errorf("%w: the new credential gave no hmac-secret output", ErrUnsuitable)
	}
	return outputs(a.HMACSecret, len(salts)), nil
}

// Derive asks for the outputs of every Theca credential on the key, with one
// verification and one touch. Credentials whose answer carries no output are
// skipped; none at all is theca.ErrNoCredential.
func (d *Device) Derive(ctx context.Context, salts [][32]byte) ([][][]byte, error) {
	if d.win != nil {
		return d.win.derive(ctx, salts)
	}
	h, err := d.hmacInput(salts)
	if err != nil {
		return nil, err
	}
	tok, err := d.token(ctx, authn.PermGetAssertion)
	if err != nil {
		return nil, err
	}
	as, err := d.k.GetAssertions(ctx, authn.GetAssertionRequest{
		RPID: RPID, ClientDataHash: random(32), Token: tok, HMACSecret: h,
	}, theca.MaxFIDO2Credentials)
	if err != nil {
		return nil, mapErr(err)
	}
	var res [][][]byte
	for _, a := range as {
		if a.HMACSecret != nil {
			res = append(res, outputs(a.HMACSecret, len(salts)))
		}
	}
	if len(res) == 0 {
		return nil, theca.ErrNoCredential
	}
	return res, nil
}

// mapErr turns the statuses a caller acts on into this package's errors,
// keeping the original in the chain.
func mapErr(err error) error {
	var se *authn.StatusError
	if !errors.As(err, &se) {
		return err
	}
	switch se.Status {
	case authn.StatusNoCredentials:
		return fmt.Errorf("%w: %w", theca.ErrNoCredential, err)
	case authn.StatusOperationDenied, authn.StatusUserActionTimeout:
		return fmt.Errorf("%w: %w", ErrNotTouched, err)
	case authn.StatusPINBlocked, authn.StatusPINAuthBlocked:
		return fmt.Errorf("%w: %w", ErrPINLocked, err)
	}
	return err
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
