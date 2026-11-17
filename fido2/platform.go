package fido2

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-mswin/webauthn"

	"github.com/go-theca/theca"
)

// The Windows route. Since Windows 10 1903 a process that is not elevated
// cannot open a FIDO HID device, so CTAP cannot be spoken directly: Windows
// speaks it, through webauthn.dll (Microsoft's webauthn.h), and this file asks
// it for the same two things the CTAP path does.
//
// What is different, and stated rather than hidden:
//   - Windows owns the PIN and the user-verification UI: a Windows Security
//     dialog appears and the person types the PIN (or uses the key's
//     fingerprint) there. The pin function Open was given is NOT called, and
//     theca's --pin-file does not apply.
//   - When several Theca credentials sit on the key, Windows asks the person to
//     choose ONE and the salts apply to that one; Derive returns that single
//     candidate, not every credential's. Unlock still works, because the
//     chosen credential's output is tried against the container.
//   - hmac-secret needs WebAuthn API version 6 (webauthn.h: the salts travel in
//     GET_ASSERTION_OPTIONS.pHmacSecretSaltValues, which is v6).

// origin is the client-data origin Windows requires to contain the RP ID; Theca
// checks no signature, so it carries no meaning.
const origin = "https://" + RPID

// credProtect3 is credProtect "user verification required" (CTAP 2.1; also
// WEBAUTHN_USER_VERIFICATION_REQUIRED in webauthn.h).
const credProtect3 = 3

// platformAPI is the part of go-mswin/webauthn this file uses; tests replace it.
type platformAPI interface {
	Register(context.Context, webauthn.RegisterRequest) (*webauthn.Registration, error)
	Assert(context.Context, webauthn.Request) (*webauthn.Assertion, error)
	APIVersion() uint32
}

type realPlatform struct{}

func (realPlatform) Register(ctx context.Context, r webauthn.RegisterRequest) (*webauthn.Registration, error) {
	return webauthn.Register(ctx, r)
}
func (realPlatform) Assert(ctx context.Context, r webauthn.Request) (*webauthn.Assertion, error) {
	return webauthn.Assert(ctx, r)
}
func (realPlatform) APIVersion() uint32 { return webauthn.APIVersion() }

// platform is a Device backend that goes through Windows.
type platform struct{ api platformAPI }

// openPlatform checks that this Windows can carry hmac-secret.
func openPlatform(api platformAPI) (*platform, error) {
	if v := api.APIVersion(); v < webauthn.HMACSecretAPIVersion {
		return nil, fmt.Errorf("%w: this Windows has WebAuthn API version %d, hmac-secret needs %d",
			ErrUnsuitable, v, webauthn.HMACSecretAPIVersion)
	}
	return &platform{api: api}, nil
}

func toSalts(salts [][32]byte) ([][32]byte, error) {
	if len(salts) == 0 || len(salts) > theca.MaxFIDO2Salts {
		return nil, fmt.Errorf("fido2: %d salts, want 1 or %d", len(salts), theca.MaxFIDO2Salts)
	}
	return salts, nil
}

func (p *platform) enroll(ctx context.Context, salts [][32]byte) ([][]byte, error) {
	if _, err := toSalts(salts); err != nil {
		return nil, err
	}
	reg, err := p.api.Register(ctx, webauthn.RegisterRequest{
		RPID: RPID, RPName: "Theca", Origin: origin,
		User:         webauthn.User{ID: random(16), Name: "theca", DisplayName: "Theca"},
		Challenge:    random(32),
		Attachment:   webauthn.CrossPlatform,
		Discoverable: true,
		Verification: webauthn.VerificationRequired,
		Attestation:  webauthn.AttestationNone,
		HMACSecret:   true,
		CredProtect:  credProtect3,
	})
	if err != nil {
		return nil, mapPlatformErr(err)
	}
	if reg.DiscoverableKnown && !reg.Discoverable {
		return nil, fmt.Errorf("%w: the key made a non-discoverable credential (no room left?)", ErrUnsuitable)
	}
	if !reg.HMACSecret || reg.CredProtect != credProtect3 {
		return nil, fmt.Errorf("%w: Windows did not confirm hmac-secret and credProtect 3 on the new credential", ErrUnsuitable)
	}
	a, err := p.api.Assert(ctx, webauthn.Request{
		RPID: RPID, Origin: origin, Challenge: random(32),
		Allow:        []webauthn.Credential{{ID: reg.CredentialID}},
		Attachment:   webauthn.CrossPlatform,
		Verification: webauthn.VerificationRequired,
		HMACSalts:    salts,
	})
	if err != nil {
		return nil, mapPlatformErr(err)
	}
	if len(a.HMACSecret) != len(salts) {
		return nil, fmt.Errorf("%w: the new credential gave no hmac-secret output", ErrUnsuitable)
	}
	return a.HMACSecret, nil
}

func (p *platform) derive(ctx context.Context, salts [][32]byte) ([][][]byte, error) {
	if _, err := toSalts(salts); err != nil {
		return nil, err
	}
	a, err := p.api.Assert(ctx, webauthn.Request{
		RPID: RPID, Origin: origin, Challenge: random(32),
		Attachment:   webauthn.CrossPlatform,
		Verification: webauthn.VerificationRequired,
		HMACSalts:    salts,
	})
	if err != nil {
		return nil, mapPlatformErr(err)
	}
	if len(a.HMACSecret) != len(salts) {
		return nil, theca.ErrNoCredential
	}
	return [][][]byte{a.HMACSecret}, nil
}

// mapPlatformErr turns Windows' answers into this package's errors.
func mapPlatformErr(err error) error {
	var we *webauthn.Error
	switch {
	case errors.Is(err, webauthn.ErrCancelled):
		return fmt.Errorf("%w: %w", ErrNotTouched, err)
	case errors.As(err, &we) && we.Cancelled():
		return fmt.Errorf("%w: %w", ErrNotTouched, err)
	case errors.As(err, &we) && we.Unavailable():
		return fmt.Errorf("%w: %w", theca.ErrNoCredential, err)
	}
	return err
}
