package fido2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	authn "github.com/go-authn/fido"

	"github.com/go-theca/theca"
)

var ctx = context.Background()

// fakeKey is a programmable authenticator: credentials hold a CredRandom and
// answer HMAC-SHA-256(CredRandom, salt), as CTAP 2.1 §12.5 describes.
type fakeKey struct {
	info    authn.Info
	retries authn.Retries
	creds   [][]byte
	closed  bool

	// Injected failures and oddities.
	infoErr, retriesErr, pinErr, uvErr, mcErr, gaErr, gasErr error
	noHMACmc                                                 bool // the credential is made without hmac-secret
	noOutput                                                 bool // GetAssertion gives no hmac-secret output
	silentIdx                                                int  // GetAssertions: this assertion (1-based) carries no output

	pinSeen string
	tokens  []authn.Permissions

	// Fingerprint scripting: uvSeq answers UVToken calls in order (nil is a
	// success), uvRetries is what getUVRetries says.
	uvSeq        []error
	uvCalls      int
	uvRetries    int
	uvRetriesErr error
}

func newFake(uv bool) *fakeKey {
	opts := map[string]bool{"rk": true, "pinUvAuthToken": true, "clientPin": true}
	if uv {
		opts["uv"] = true
	}
	return &fakeKey{
		info:    authn.Info{Extensions: []string{"hmac-secret", "credProtect"}, Options: opts, PINProtocols: []uint{2, 1}},
		retries: authn.Retries{PIN: 8},
	}
}

func (f *fakeKey) GetInfo(context.Context) (authn.Info, error) { return f.info, f.infoErr }
func (f *fakeKey) PINRetries(context.Context) (authn.Retries, error) {
	return f.retries, f.retriesErr
}
func (f *fakeKey) PINToken(_ context.Context, pin string, _ authn.PINProtocol, p authn.Permissions, _ string) (authn.Token, error) {
	f.pinSeen = pin
	f.tokens = append(f.tokens, p)
	return authn.Token{}, f.pinErr
}
func (f *fakeKey) UVToken(_ context.Context, _ authn.PINProtocol, p authn.Permissions, _ string) (authn.Token, error) {
	f.uvCalls++
	if len(f.uvSeq) > 0 { // a scripted run of answers, one per call
		err := f.uvSeq[0]
		f.uvSeq = f.uvSeq[1:]
		if err != nil {
			return authn.Token{}, err
		}
		f.tokens = append(f.tokens, p)
		return authn.Token{}, nil
	}
	f.tokens = append(f.tokens, p)
	return authn.Token{}, f.uvErr
}

func (f *fakeKey) UVRetries(context.Context) (int, error) { return f.uvRetries, f.uvRetriesErr }
func (f *fakeKey) MakeCredential(_ context.Context, r authn.MakeCredentialRequest) (*authn.Attestation, error) {
	if f.mcErr != nil {
		return nil, f.mcErr
	}
	if r.RP.ID != RPID || !r.Options["rk"] || len(r.User.ID) != 16 {
		return nil, errors.New("fake: unexpected registration request")
	}
	cr := bytes.Repeat([]byte{byte(len(f.creds) + 1)}, 32)
	f.creds = append(f.creds, cr)
	att := &authn.Attestation{}
	att.Parsed.CredentialID = []byte{byte(len(f.creds))}
	att.Extensions.HMACSecret = !f.noHMACmc
	att.Extensions.CredProtect = r.Extensions.CredProtect
	return att, nil
}

func out(cr, salt []byte) []byte {
	h := hmac.New(sha256.New, cr)
	h.Write(salt)
	return h.Sum(nil)
}

func (f *fakeKey) answer(cr []byte, h *authn.HMACSecret) *authn.HMACSecretOutput {
	o := &authn.HMACSecretOutput{First: out(cr, h.Salt1)}
	if h.Salt2 != nil {
		o.Second = out(cr, h.Salt2)
	}
	return o
}

func (f *fakeKey) GetAssertion(_ context.Context, r authn.GetAssertionRequest) (*authn.Assertion, error) {
	if f.gaErr != nil {
		return nil, f.gaErr
	}
	cr := f.creds[int(r.Allow[0].ID[0])-1]
	a := &authn.Assertion{}
	if !f.noOutput {
		a.HMACSecret = f.answer(cr, r.HMACSecret)
	}
	return a, nil
}

func (f *fakeKey) GetAssertions(_ context.Context, r authn.GetAssertionRequest, max int) ([]*authn.Assertion, error) {
	if f.gasErr != nil {
		return nil, f.gasErr
	}
	if len(r.Allow) != 0 || max != theca.MaxFIDO2Credentials {
		return nil, errors.New("fake: a walk must have an empty allow list and theca's bound")
	}
	if len(f.creds) == 0 {
		return nil, &authn.StatusError{Status: authn.StatusNoCredentials}
	}
	var as []*authn.Assertion
	for i := len(f.creds) - 1; i >= 0; i-- { // newest first
		a := &authn.Assertion{}
		if len(as)+1 != f.silentIdx {
			a.HMACSecret = f.answer(f.creds[i], r.HMACSecret)
		}
		as = append(as, a)
	}
	return as, nil
}

func (f *fakeKey) Close() error { f.closed = true; return nil }

func pinFn(p string) func() (string, error) { return func() (string, error) { return p, nil } }

func withFake(t *testing.T, f *fakeKey, err error) {
	t.Helper()
	saved := openKey
	t.Cleanup(func() { openKey = saved })
	openKey = func(context.Context) (key, error) {
		if err != nil {
			return nil, err
		}
		return f, nil
	}
}

func salts(n int) [][32]byte {
	s := make([][32]byte, n)
	for i := range s {
		s[i][0] = byte(0x10 + i)
	}
	return s
}

func TestEnrollThenDeriveFindsTheSameOutputs(t *testing.T) {
	for _, uv := range []bool{false, true} {
		f := newFake(uv)
		withFake(t, f, nil)
		d, err := Open(ctx, pinFn("123456"))
		if err != nil {
			t.Fatal(err)
		}
		if d.proto != authn.PINProtocolTwo {
			t.Fatal("protocol 2 not preferred")
		}
		for _, n := range []int{1, 2} {
			got, err := d.Enroll(ctx, salts(n))
			if err != nil || len(got) != n {
				t.Fatalf("uv=%v n=%d: enrol %d outputs, %v", uv, n, len(got), err)
			}
			res, err := d.Derive(ctx, salts(n))
			if err != nil {
				t.Fatal(err)
			}
			// The newest credential answers first, with the same outputs.
			for j := range n {
				if !bytes.Equal(res[0][j], got[j]) {
					t.Fatalf("uv=%v n=%d: derive differs from enrol at salt %d", uv, n, j)
				}
			}
		}
		if !uv && f.pinSeen != "123456" {
			t.Fatal("the PIN function's answer was not used")
		}
		if uv && f.pinSeen != "" {
			t.Fatal("a PIN was asked of a key with its own verification")
		}
		want := []authn.Permissions{authn.PermMakeCredential, authn.PermGetAssertion, authn.PermGetAssertion}
		if len(f.tokens) < 3 || f.tokens[0] != want[0] || f.tokens[1] != want[1] || f.tokens[2] != want[2] {
			t.Fatalf("token permissions %v", f.tokens)
		}
		d.Close()
		if !f.closed {
			t.Fatal("Close did not close the key")
		}
	}
}

func TestDeriveSkipsAnswersWithoutOutput(t *testing.T) {
	f := newFake(true)
	withFake(t, f, nil)
	d, _ := Open(ctx, nil)
	first, _ := d.Enroll(ctx, salts(1))
	d.Enroll(ctx, salts(1))
	f.silentIdx = 1 // the newest credential answers without output
	res, err := d.Derive(ctx, salts(1))
	if err != nil || len(res) != 1 || !bytes.Equal(res[0][0], first[0]) {
		t.Fatalf("expected only the older credential: %d %v", len(res), err)
	}
	// Every answer silent: no credential to try.
	f.creds = f.creds[:1]
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatalf("all silent: %v", err)
	}
	// No credential at all on the key: the status maps to ErrNoCredential.
	f.creds, f.silentIdx = nil, 0
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatalf("empty key: %v", err)
	}
}

func TestOpenRefusesUnsuitableKeys(t *testing.T) {
	boom := errors.New("no key attached")
	withFake(t, nil, boom)
	if _, err := Open(ctx, pinFn("x")); !errors.Is(err, boom) {
		t.Fatalf("open error: %v", err)
	}
	for name, mutate := range map[string]func(f *fakeKey){
		"info error":      func(f *fakeKey) { f.infoErr = boom },
		"no hmac-secret":  func(f *fakeKey) { f.info.Extensions = []string{"credProtect"} },
		"no credProtect":  func(f *fakeKey) { f.info.Extensions = []string{"hmac-secret"} },
		"no rk":           func(f *fakeKey) { delete(f.info.Options, "rk") },
		"no token":        func(f *fakeKey) { delete(f.info.Options, "pinUvAuthToken") },
		"no PIN set":      func(f *fakeKey) { delete(f.info.Options, "clientPin") },
		"protocol 1 only": nil,
	} {
		f := newFake(false)
		if mutate == nil {
			f.info.PINProtocols = []uint{1}
			withFake(t, f, nil)
			d, err := Open(ctx, pinFn("x"))
			if err != nil || d.proto != authn.PINProtocolOne {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		mutate(f)
		withFake(t, f, nil)
		if _, err := Open(ctx, pinFn("x")); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !f.closed {
			t.Errorf("%s: the refused key was not closed", name)
		}
	}
	// No built-in verification and no way to ask for a PIN.
	f := newFake(false)
	withFake(t, f, nil)
	if _, err := Open(ctx, nil); !errors.Is(err, ErrUnsuitable) {
		t.Fatalf("no PIN function: %v", err)
	}
}

func TestEnrollAndDeriveErrors(t *testing.T) {
	boom := errors.New("boom")
	denied := &authn.StatusError{Status: authn.StatusOperationDenied}
	blocked := &authn.StatusError{Status: authn.StatusPINBlocked}
	other := &authn.StatusError{Status: authn.StatusPINInvalid}
	cases := map[string]struct {
		uv     bool
		mutate func(f *fakeKey)
		pin    func() (string, error)
		want   error
		derive bool
	}{
		"too many salts":       {mutate: func(*fakeKey) {}, want: nil},
		"retries unreadable":   {mutate: func(f *fakeKey) { f.retriesErr = boom }, want: boom},
		"PIN at zero":          {mutate: func(f *fakeKey) { f.retries.PIN = 0 }, want: ErrPINLocked},
		"power cycle":          {mutate: func(f *fakeKey) { f.retries.PowerCycle = true }, want: ErrPINLocked},
		"PIN not given":        {mutate: func(*fakeKey) {}, pin: func() (string, error) { return "", boom }, want: boom},
		"PIN refused":          {mutate: func(f *fakeKey) { f.pinErr = other }, want: other},
		"PIN blocked":          {mutate: func(f *fakeKey) { f.pinErr = blocked }, want: ErrPINLocked},
		"UV not touched":       {uv: true, mutate: func(f *fakeKey) { f.uvErr = denied }, want: ErrNotTouched},
		"register refused":     {mutate: func(f *fakeKey) { f.mcErr = denied }, want: ErrNotTouched},
		"no hmac-secret made":  {mutate: func(f *fakeKey) { f.noHMACmc = true }, want: ErrUnsuitable},
		"assert failed":        {mutate: func(f *fakeKey) { f.gaErr = boom }, want: boom},
		"no output at enrol":   {mutate: func(f *fakeKey) { f.noOutput = true }, want: ErrUnsuitable},
		"walk failed":          {mutate: func(f *fakeKey) { f.gasErr = boom }, want: boom, derive: true},
		"walk not touched":     {mutate: func(f *fakeKey) { f.gasErr = &authn.StatusError{Status: authn.StatusUserActionTimeout} }, want: ErrNotTouched, derive: true},
		"derive token refused": {uv: true, mutate: func(f *fakeKey) { f.uvErr = boom }, want: boom, derive: true},
	}
	for name, c := range cases {
		f := newFake(c.uv)
		withFake(t, f, nil)
		pin := c.pin
		if pin == nil {
			pin = pinFn("123456")
		}
		d, err := Open(ctx, pin)
		if err != nil {
			t.Fatalf("%s: open: %v", name, err)
		}
		c.mutate(f)
		if name == "too many salts" {
			if _, err := d.Enroll(ctx, salts(3)); err == nil {
				t.Error("3 salts accepted by Enroll")
			}
			if _, err := d.Derive(ctx, nil); err == nil {
				t.Error("0 salts accepted by Derive")
			}
			continue
		}
		if c.derive {
			_, err = d.Derive(ctx, salts(1))
		} else {
			_, err = d.Enroll(ctx, salts(1))
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// The second verification of Enrol failing.
	f := newFake(true)
	withFake(t, f, nil)
	d, _ := Open(ctx, nil)
	n := 0
	d.k = &failSecondUV{fakeKey: f, n: &n}
	if _, err := d.Enroll(ctx, salts(1)); !errors.Is(err, boomUV) {
		t.Fatalf("second token: %v", err)
	}
}

var boomUV = errors.New("second verification failed")

type failSecondUV struct {
	*fakeKey
	n *int
}

func (f *failSecondUV) UVToken(ctx context.Context, p authn.PINProtocol, perm authn.Permissions, rp string) (authn.Token, error) {
	*f.n++
	if *f.n == 2 {
		return authn.Token{}, boomUV
	}
	return f.fakeKey.UVToken(ctx, p, perm, rp)
}

// TestTheTransportIsReached: on a machine without a key (CI) the real
// transport answers an error; with one attached it opens. Either way the
// call goes through go-macos/fido.
func TestTheTransportIsReached(t *testing.T) {
	k, err := openKey(ctx) // the default, which is openTransport
	if err == nil {
		k.Close()
	}
}

// The built-in verification paths (CTAP 2.1 6.4 "uv", 6.5.5.7.3).

func statusErr(s authn.Status) error { return &authn.StatusError{Status: s} }

// bio is a Bio-like fake: uv configured and a PIN set.
func bio(t *testing.T, f *fakeKey, pin func() (string, error)) (*Device, *[]string) {
	t.Helper()
	f.info.Options["uv"] = true
	withFake(t, f, nil)
	var said []string
	d, err := Open(ctx, pin, WithNotice(func(s string) { said = append(said, s) }))
	if err != nil {
		t.Fatal(err)
	}
	return d, &said
}

func TestUVIsUsedOnlyWhenConfigured(t *testing.T) {
	// "uv" false: capable but no finger enrolled -> the PIN, no UV call.
	f := newFake(false)
	f.info.Options["uv"] = false
	withFake(t, f, nil)
	d, err := Open(ctx, pinFn("1234"))
	if err != nil || d.uv {
		t.Fatalf("uv=false key: %v uv=%v", err, d.uv)
	}
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, theca.ErrNoCredential) || f.uvCalls != 0 || f.pinSeen != "1234" {
		t.Fatalf("expected a PIN-only walk: %v uvCalls=%d pin=%q", err, f.uvCalls, f.pinSeen)
	}
}

func TestOneVerificationPerUnlockWithAFingerprint(t *testing.T) {
	f := newFake(false)
	d, said := bio(t, f, pinFn("1234"))
	if _, err := d.Enroll(ctx, salts(1)); err != nil {
		t.Fatal(err)
	}
	f.uvCalls, f.tokens = 0, nil
	if _, err := d.Derive(ctx, salts(1)); err != nil {
		t.Fatal(err)
	}
	// One token, one UV: the key sets userPresent itself (6.5.5.7.3 step 3.12),
	// so getAssertion asks for no second touch (6.2.2 step 9.1.2).
	if f.uvCalls != 1 || len(f.tokens) != 1 || len(*said) != 0 {
		t.Fatalf("uvCalls=%d tokens=%v said=%v", f.uvCalls, f.tokens, *said)
	}
}

func TestAFingerprintThatFailsFallsBackToThePIN(t *testing.T) {
	invalid, blocked, notAllowed := statusErr(statusUVInvalid), statusErr(statusUVBlocked), statusErr(statusNotAllowed)
	cases := map[string]struct {
		seq     []error
		retries int
		rerr    error
		reason  string
		uvCalls int
	}{
		"blocked":              {seq: []error{blocked}, reason: "the fingerprint is blocked", uvCalls: 1},
		"not configured":       {seq: []error{notAllowed}, reason: "no fingerprint is enrolled", uvCalls: 1},
		"invalid, none left":   {seq: []error{invalid}, retries: 0, reason: "the fingerprint was not recognised", uvCalls: 1},
		"invalid, unreadable":  {seq: []error{invalid}, rerr: errors.New("boom"), reason: "the fingerprint was not recognised", uvCalls: 1},
		"invalid then blocked": {seq: []error{invalid, blocked}, retries: 2, reason: "the fingerprint is blocked", uvCalls: 2},
		"always invalid":       {seq: []error{invalid, invalid, invalid, invalid, invalid, invalid}, retries: 9, reason: "the fingerprint was not recognised", uvCalls: maxUVAttempts},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(false)
			f.uvSeq, f.uvRetries, f.uvRetriesErr = c.seq, c.retries, c.rerr
			d, said := bio(t, f, pinFn("1234"))
			if _, err := d.Enroll(ctx, salts(1)); err != nil {
				t.Fatal(err)
			}
			if f.pinSeen != "1234" || f.uvCalls != c.uvCalls || d.uv {
				t.Fatalf("pin=%q uvCalls=%d (want %d) uv=%v", f.pinSeen, f.uvCalls, c.uvCalls, d.uv)
			}
			if last := (*said)[len(*said)-1]; last != c.reason+" — using the PIN." {
				t.Fatalf("last notice %q", last)
			}
			// The second token of the enrolment went straight to the PIN.
			if len(f.tokens) != 2 || f.uvCalls != c.uvCalls {
				t.Fatalf("tokens %v uvCalls %d", f.tokens, f.uvCalls)
			}
		})
	}
}

func TestARetryShowsTheTriesLeftAndThenSucceeds(t *testing.T) {
	f := newFake(false)
	f.uvSeq, f.uvRetries = []error{statusErr(statusUVInvalid), nil}, 2
	d, said := bio(t, f, pinFn("1234"))
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatal(err)
	}
	if len(*said) != 1 || (*said)[0] != "Fingerprint not recognised (2 tries left); try again." || f.pinSeen != "" {
		t.Fatalf("said %v pin %q", *said, f.pinSeen)
	}
}

func TestNoPINToFallBackToIsAnErrorNotAHang(t *testing.T) {
	for name, mk := range map[string]func(f *fakeKey) func() (string, error){
		"no PIN function": func(*fakeKey) func() (string, error) { return nil },
		"no PIN set":      func(f *fakeKey) func() (string, error) { delete(f.info.Options, "clientPin"); return pinFn("1") },
	} {
		f := newFake(false)
		f.uvSeq = []error{statusErr(statusUVBlocked)}
		d, _ := bio(t, f, mk(f))
		if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, ErrUVLocked) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestATouchRefusedOnABioKeyIsNotAUVFailure(t *testing.T) {
	f := newFake(false)
	f.uvSeq = []error{statusErr(authn.StatusUserActionTimeout)}
	d, said := bio(t, f, pinFn("1234"))
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, ErrNotTouched) || f.pinSeen != "" || len(*said) != 0 {
		t.Fatalf("%v pin=%q said=%v", err, f.pinSeen, *said)
	}
}

func TestNoNoticeSinkIsFine(t *testing.T) {
	f := newFake(false)
	f.uvSeq = []error{statusErr(statusUVBlocked)}
	f.info.Options["uv"] = true
	withFake(t, f, nil)
	d, _ := Open(ctx, pinFn("1234"))
	if _, err := d.Derive(ctx, salts(1)); !errors.Is(err, theca.ErrNoCredential) {
		t.Fatal(err)
	}
}
