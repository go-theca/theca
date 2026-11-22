package theca

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/journal"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/merkle"
)

func TestMain(m *testing.M) {
	// Small Argon2id profiles: the production table is 2 GiB and up.
	kdf.Table = [3]kdf.Profile{{Time: 1, MemKiB: 64, Threads: 1}, {Time: 2, MemKiB: 64, Threads: 2}, {Time: 1, MemKiB: 128, Threads: 1}}
	os.Exit(m.Run())
}

// memFile is a Backing with fault injection: after failAfter writes every
// write fails, like a power cut.
type memFile struct {
	b         []byte
	writes    int
	failAfter int // -1: never
	syncFail  bool
	syncs     int // Sync calls so far
	syncCut   int // from the syncCut-th Sync on (1-based) every Sync fails; 0: never
}

func newMem(n int) *memFile { return &memFile{b: make([]byte, n), failAfter: -1} }

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

var errCut = errors.New("power cut")

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	if m.failAfter >= 0 && m.writes >= m.failAfter {
		return 0, errCut
	}
	m.writes++
	if off < 0 || int(off)+len(p) > len(m.b) {
		return 0, io.ErrShortWrite
	}
	return copy(m.b[off:], p), nil
}

func (m *memFile) Sync() error {
	m.syncs++
	if m.syncFail || (m.syncCut > 0 && m.syncs >= m.syncCut) {
		return errCut
	}
	return nil
}
func (m *memFile) Size() (int64, error) { return int64(len(m.b)), nil }

// clone returns an independent copy of the bytes, as after a crash.
func (m *memFile) clone() *memFile {
	return &memFile{b: append([]byte(nil), m.b...), failAfter: -1}
}

const (
	testSectors = 200
	testJournal = 8
)

var ctx = context.Background()

func create(t testing.TB, policy Policy) (*Container, *memFile, string) {
	return createJ(t, policy, testJournal)
}

func createJ(t testing.TB, policy Policy, journalEntries uint32) (*Container, *memFile, string) {
	t.Helper()
	geo, err := format.NewGeometry(testSectors, journalEntries)
	if err != nil {
		t.Fatal(err)
	}
	f := newMem(int(geo.End))
	c, code, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: journalEntries,
		Password: []byte("correct horse"), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, string(code)
}

func pwUnlock() Unlock { return Unlock{Password: []byte("correct horse")} }

// randomFactor is an arbitrary single factor for filling slots: not a FIDO2
// key, which never opens a slot alone.
func randomFactor() Factor {
	var f Factor
	f.Kind = "rc"
	rand.Read(f.KEK[:])
	return f
}

func TestKeyAloneSlotRefused(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	if err := c.AddSlot(FIDO2Factor(rnd(32))); !errors.Is(err, ErrOption) {
		t.Fatalf("a slot for the key alone: %v", err)
	}
	if err := c.AddSlot(FIDO2Factor(rnd(32)), randomFactor()); err != nil {
		t.Fatalf("a key with a partner: %v", err)
	}
}

func reopen(t testing.TB, f Backing, u Unlock) *Container {
	t.Helper()
	c, err := Open(ctx, f, u, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// model is a plain byte slice the container must agree with.
type model []byte

func (m model) check(t testing.TB, c *Container) {
	t.Helper()
	got := make([]byte, len(m))
	if n, err := c.ReadAt(got, 0); err != nil || n != len(m) {
		t.Fatalf("read all: %d %v", n, err)
	}
	if !bytes.Equal(got, m) {
		for i := range got {
			if got[i] != m[i] {
				t.Fatalf("content differs from the model at byte %d", i)
			}
		}
	}
}

func put(t testing.TB, c *Container, m model, off int, data []byte) {
	t.Helper()
	if n, err := c.WriteAt(data, int64(off)); err != nil || n != len(data) {
		t.Fatalf("write %d at %d: %d %v", len(data), off, n, err)
	}
	copy(m[off:], data)
}

func rnd(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestRoundTrip(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	m := make(model, testSectors*SectorSize)
	m.check(t, c) // all zeros before anything is written
	put(t, c, m, 0, rnd(10))
	put(t, c, m, 4090, rnd(20))       // straddles two sectors
	put(t, c, m, 100*4096, rnd(9000)) // spans three sectors, unaligned end
	put(t, c, m, 199*4096+4000, rnd(96))
	put(t, c, m, 5, rnd(3))
	m.check(t, c)
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if info := c.Info(); info.Epoch == 0 || info.Sectors != testSectors || info.SlotsUsed != 2 || info.RollbackProtected {
		t.Fatalf("info %+v", info)
	}
	if n, err := c.Verify(); err != nil || n != testSectors {
		t.Fatalf("verify: %d %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Fatal("use after close")
	}
	if err := c.Close(); !errors.Is(err, ErrClosed) {
		t.Fatal("double close")
	}

	for _, u := range []Unlock{pwUnlock(), {Recovery: []byte(code)}} {
		c2 := reopen(t, f, u)
		m.check(t, c2)
		if n, err := c2.Verify(); err != nil || n != testSectors {
			t.Fatalf("verify after reopen: %v", err)
		}
		c2.Close()
	}
}

func TestEverythingLooksRandom(t *testing.T) {
	// No magic, no plaintext (DESIGN 9.1): every 4 KiB block of a fresh
	// container, and of a used one, has near-uniform bytes.
	c, f, _ := create(t, PolicyAny)
	put(t, c, make(model, testSectors*SectorSize), 0, bytes.Repeat([]byte("A"), 50000))
	c.Sync()
	geo, _ := format.NewGeometry(testSectors, testJournal)
	for off := 0; off+4096 <= len(f.b); off += 4096 {
		// Known limit, DESIGN section 19 I11: tree nodes are plain HMAC
		// values, and the constant value of an unwritten child repeats in
		// them, so the tree area shows how sparse the container is.
		if uint64(off) >= geo.TreeOff && uint64(off) < geo.DataOff {
			continue
		}
		var seen [256]int
		for _, v := range f.b[off : off+4096] {
			seen[v]++
		}
		// A byte's count in a random block is Binomial(4096, 1/256), about
		// Poisson(16). The bound must hold for EVERY cell of the run: about
		// 256 blocks × 256 values = 65 536 cells. "n > 40" looked far out
		// (it is 6 standard deviations) but the Poisson tail there is
		// ~1.3e-7 per cell, so ~0.85 % of runs failed on random data: 8 of
		// 600 measured, on main and on a branch alike (PR #12's CI). At 55
		// the tail is ~1.5e-14 per cell, ~1e-9 per run. Plaintext still
		// trips it: a block of one repeated byte has a count of 4096.
		for v, n := range seen {
			if n > 55 {
				t.Fatalf("block at %d: byte %#x occurs %d times", off, v, n)
			}
		}
	}
}

func TestWrongFactors(t *testing.T) {
	_, f, code := create(t, PolicyAny)
	_ = code
	bad := []Unlock{
		{}, {Password: []byte("wrong")}, {Password: []byte("correct horse "), Hint: 0},
		{Recovery: []byte("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-A")[:0]},
	}
	for _, u := range bad {
		if _, err := Open(ctx, f, u, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
			t.Errorf("%+v: %v", u, err)
		}
	}
	// Another hint derives another key.
	if _, err := Open(ctx, f, Unlock{Password: []byte("correct horse"), Hint: 1}, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("wrong hint: %v", err)
	}
	if _, err := Open(ctx, f, Unlock{Password: []byte("x"), Hint: 9}, OpenOptions{}); !errors.Is(err, kdf.ErrProfile) {
		t.Errorf("hint outside the table: %v", err)
	}
	if _, err := Open(ctx, f, Unlock{Recovery: []byte("not a code")}, OpenOptions{}); !errors.Is(err, format.ErrRecoveryCode) {
		t.Errorf("malformed code: %v", err)
	}
	// A valid code of another container.
	_, other, code2 := create(t, PolicyAny)
	_ = other
	if _, err := Open(ctx, f, Unlock{Recovery: []byte(code2)}, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("foreign recovery code: %v", err)
	}
	// Not a container at all, and files too short to be one.
	junk := newMem(len(f.b))
	rand.Read(junk.b)
	if _, err := Open(ctx, junk, pwUnlock(), OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("random file: %v", err)
	}
	if _, err := Open(ctx, newMem(100), pwUnlock(), OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("short file: %v", err)
	}
}

// fakeKey plays a FIDO2 authenticator holding discoverable Theca
// credentials: a CredRandom per credential and HMAC-SHA-256 over each salt,
// written from the CTAP 2.1 hmac-secret description (§12.5). Every call is
// one touch on a real key, and is counted.
type fakeKey struct {
	creds   [][]byte // CredRandom of each credential, in creation order
	derives int
	enrolls int
	salts   [][32]byte // the salts of the last call
	failErr error
}

func newKey() *fakeKey { return &fakeKey{} }

func (k *fakeKey) out(cr []byte, salts [][32]byte) [][]byte {
	outs := make([][]byte, len(salts))
	for j, s := range salts {
		h := hmac.New(sha256.New, cr)
		h.Write(s[:])
		outs[j] = h.Sum(nil)
	}
	return outs
}

// record keeps a COPY of the salts, as a real key receives them over the
// wire: the caller wipes its own after the call.
func (k *fakeKey) record(salts [][32]byte) { k.salts = append([][32]byte(nil), salts...) }

func (k *fakeKey) Enroll(_ context.Context, salts [][32]byte) ([][]byte, error) {
	k.enrolls++
	k.record(salts)
	cr := rnd(32)
	k.creds = append(k.creds, cr)
	return k.out(cr, salts), nil
}

func (k *fakeKey) Derive(_ context.Context, salts [][32]byte) ([][][]byte, error) {
	k.derives++
	k.record(salts)
	if k.failErr != nil {
		return nil, k.failErr
	}
	if len(k.creds) == 0 {
		return nil, ErrNoCredential
	}
	var res [][][]byte
	for _, cr := range k.creds {
		res = append(res, k.out(cr, salts))
	}
	return res, nil
}

func TestTwoOfThreeWithFIDO2(t *testing.T) {
	c, f, code := create(t, PolicyTwoOfThree)
	m := make(model, testSectors*SectorSize)
	put(t, c, m, 777, rnd(5000))
	salt := make([]byte, format.SaltSize)
	f.ReadAt(salt, 0)
	pw, _ := PasswordFactor(0, []byte("correct horse"), salt)
	rc, _ := RecoveryFactor([]byte(code))
	key := newKey()
	if err := c.EnrollFIDO2(ctx, key, pw, rc); err != nil {
		t.Fatal(err)
	}
	if c.Info().SlotsUsed != 1+2 { // {pw,rc}, then {pw,key} and {rc,key}: no locators
		t.Fatalf("slots used: %d", c.Info().SlotsUsed)
	}
	if key.enrolls != 1 {
		t.Fatalf("enrolment took %d touches, want 1 (both salts in one request)", key.enrolls)
	}
	c.Close()

	open := func(u Unlock) error {
		c, err := Open(ctx, f, u, OpenOptions{})
		if err == nil {
			m.check(t, c)
			c.Close()
		}
		return err
	}
	for name, u := range map[string]Unlock{
		"password+recovery": {Password: []byte("correct horse"), Recovery: []byte(code)},
		"password+key":      {Password: []byte("correct horse"), FIDO: key},
		"recovery+key":      {Recovery: []byte(code), FIDO: key},
		"all three":         {Password: []byte("correct horse"), Recovery: []byte(code), FIDO: key},
	} {
		if err := open(u); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// One factor alone never opens it, whichever it is.
	for name, u := range map[string]Unlock{
		"password": {Password: []byte("correct horse")},
		"recovery": {Recovery: []byte(code)},
		"key":      {FIDO: key},
	} {
		if err := open(u); !errors.Is(err, ErrNoMatch) {
			t.Errorf("%s alone: %v", name, err)
		}
	}
	// A different key (no matching credential) does not help.
	if err := open(Unlock{Password: []byte("correct horse"), FIDO: newKey()}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("foreign key: %v", err)
	}
	// A wrong password with the right key does not either.
	if err := open(Unlock{Password: []byte("nope"), FIDO: key}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("wrong password + key: %v", err)
	}
	// A key that fails for a real reason surfaces that reason.
	boom := errors.New("no key attached")
	if err := open(Unlock{Password: []byte("correct horse"), FIDO: &fakeKey{failErr: boom}}); !errors.Is(err, boom) {
		t.Errorf("key error not surfaced: %v", err)
	}
	// One question per unlock, whatever the number of partners: the
	// password+recovery+key unlock asked once, with two salts.
	before := key.derives
	if err := open(Unlock{Password: []byte("correct horse"), Recovery: []byte(code), FIDO: key}); err != nil {
		t.Fatal(err)
	}
	if key.derives != before+1 || len(key.salts) != 2 {
		t.Fatalf("one unlock asked the key %d times with %d salts", key.derives-before, len(key.salts))
	}
	// The key alone is never asked (it pairs with a partner).
	before = key.derives
	open(Unlock{FIDO: key})
	if key.derives != before {
		t.Fatal("a key with no partner was asked")
	}
	if err := c.EnrollFIDO2(ctx, key, pw); err == nil {
		t.Error("closed container enrolled a key")
	}
}

// TestFIDO2SaltFollowsThePartner (DESIGN 19, I21): the salt the key is asked
// for is derived from the partner factor, so a wrong password asks the key
// for a DIFFERENT salt (one touch-gated question per guess, no offline test),
// and nothing about the key is stored in the container.
func TestFIDO2SaltFollowsThePartner(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	salt := make([]byte, format.SaltSize)
	f.ReadAt(salt, 0)
	pw, _ := PasswordFactor(0, []byte("correct horse"), salt)
	key := newKey()
	before := c.Info().SlotsUsed
	if err := c.EnrollFIDO2(ctx, key, pw); err != nil {
		t.Fatal(err)
	}
	// Nothing but the pairwise wrap slot is stored for the key.
	if got := c.Info().SlotsUsed; got != before+1 {
		t.Fatalf("enrolment stored %d slots, want 1", got-before)
	}
	enrolled := key.salts[0]
	c.Close()
	r, err := Open(ctx, f, Unlock{Password: []byte("correct horse"), FIDO: key}, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if key.salts[0] != enrolled {
		t.Fatal("the right password asked for another salt")
	}
	// The wrong password is refused by its own slot too, so Open fails; what
	// matters is the salt the key was asked for.
	if _, err := Open(ctx, f, Unlock{Password: []byte("wrong guess"), FIDO: key}, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if key.salts[0] == enrolled {
		t.Fatal("a wrong password asked for the enrolled salt")
	}
	if enrolled == ([32]byte{}) {
		t.Fatal("the key was handed a zero salt")
	}
}

// TestSaltsAreWipedAfterTheCall: the caller's salts are password-equivalent
// (I21) and must not outlive the call.
func TestSaltsAreWipedAfterTheCall(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	c.Close()
	spy := &spyKey{}
	Open(ctx, f, Unlock{Password: []byte("correct horse"), FIDO: spy}, OpenOptions{})
	if spy.seen == nil || spy.seen[0] != ([32]byte{}) {
		t.Fatal("unlock salts not wiped")
	}
	r := reopen(t, f, pwUnlock())
	pw := randomFactor()
	r.EnrollFIDO2(ctx, spy, pw)
	if spy.seen[0] != ([32]byte{}) {
		t.Fatal("enrolment salts not wiped")
	}
}

// spyKey keeps a REFERENCE to the caller's salts, to see them wiped.
type spyKey struct{ seen [][32]byte }

func (s *spyKey) Enroll(_ context.Context, salts [][32]byte) ([][]byte, error) {
	s.seen = salts
	return [][]byte{rnd(32)}, nil
}

func (s *spyKey) Derive(_ context.Context, salts [][32]byte) ([][][]byte, error) {
	s.seen = salts
	return nil, ErrNoCredential
}

// TestTwoKeysAndManyCredentials: every Theca credential on a key is tried
// from ONE answer, and two enrolled keys each open the container.
func TestTwoKeysAndManyCredentials(t *testing.T) {
	c, f, code := create(t, PolicyTwoOfThree)
	salt := make([]byte, format.SaltSize)
	f.ReadAt(salt, 0)
	pw, _ := PasswordFactor(0, []byte("correct horse"), salt)
	rc, _ := RecoveryFactor([]byte(code))
	k1, k2 := newKey(), newKey()
	k1.creds = [][]byte{rnd(32), rnd(32)} // credentials of other containers
	if err := c.EnrollFIDO2(ctx, k1, pw, rc); err != nil {
		t.Fatal(err)
	}
	k1.creds = append(k1.creds, rnd(32)) // and one made later
	if err := c.EnrollFIDO2(ctx, k2, pw); err != nil {
		t.Fatal(err)
	}
	c.Close()
	for name, u := range map[string]Unlock{
		"k1 + password": {Password: []byte("correct horse"), FIDO: k1},
		"k1 + recovery": {Recovery: []byte(code), FIDO: k1},
		"k2 + password": {Password: []byte("correct horse"), FIDO: k2},
	} {
		r, err := Open(ctx, f, u, OpenOptions{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		r.Close()
	}
	// k2 was enrolled with the password only.
	if _, err := Open(ctx, f, Unlock{Recovery: []byte(code), FIDO: k2}, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("k2 + recovery: %v", err)
	}
}

// badKey answers malformed outputs.
type badKey struct {
	fakeKey
	enrollOuts [][]byte
	deriveOuts [][][]byte
}

func (b *badKey) Enroll(context.Context, [][32]byte) ([][]byte, error) { return b.enrollOuts, nil }
func (b *badKey) Derive(context.Context, [][32]byte) ([][][]byte, error) {
	return b.deriveOuts, nil
}

func TestMalformedAuthenticatorAnswers(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	pw := Factor{Kind: "pw", KEK: [32]byte{1}}
	for name, outs := range map[string][][]byte{
		"no output":    nil,
		"two for one":  {rnd(32), rnd(32)},
		"short output": {rnd(31)},
	} {
		if err := c.EnrollFIDO2(ctx, &badKey{enrollOuts: outs}, pw); !errors.Is(err, ErrAuthenticator) {
			t.Errorf("enrol, %s: %v", name, err)
		}
	}
	if c.Info().SlotsUsed != 2 {
		t.Fatalf("a refused enrolment used slots: %d", c.Info().SlotsUsed)
	}
	c.Close()
	many := make([][][]byte, MaxFIDO2Credentials+1)
	for i := range many {
		many[i] = [][]byte{rnd(32)}
	}
	for name, creds := range map[string][][][]byte{
		"wrong count":  {{rnd(32), rnd(32)}},
		"short output": {{rnd(16)}},
		"too many":     many,
	} {
		_, err := Open(ctx, f, Unlock{Password: []byte("correct horse"), FIDO: &badKey{deriveOuts: creds}}, OpenOptions{})
		if !errors.Is(err, ErrAuthenticator) {
			t.Errorf("unlock, %s: %v", name, err)
		}
	}
	// Exactly the maximum is accepted (and simply finds nothing extra).
	r, err := Open(ctx, f, Unlock{Password: []byte("correct horse"), FIDO: &badKey{deriveOuts: many[:MaxFIDO2Credentials]}}, OpenOptions{})
	if err != nil {
		t.Fatalf("at the maximum: %v", err)
	}
	r.Close()
	// A key with no Theca credential is routine: the password alone opens.
	r, err = Open(ctx, f, Unlock{Password: []byte("correct horse"), FIDO: newKey()}, OpenOptions{})
	if err != nil {
		t.Fatalf("empty key: %v", err)
	}
	r.Close()
}

func TestEnrollRefusals(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	if err := c.EnrollFIDO2(ctx, newKey()); !errors.Is(err, ErrOption) {
		t.Fatal("enrolment without a partner")
	}
	pw := Factor{Kind: "pw"}
	if err := c.EnrollFIDO2(ctx, newKey(), pw, pw, pw); !errors.Is(err, ErrOption) {
		t.Fatal("enrolment with three partners (hmac-secret carries two salts)")
	}
	bad := &enrollFails{}
	if err := c.EnrollFIDO2(ctx, bad, pw); err == nil {
		t.Fatal("enrol error swallowed")
	}
}

type enrollFails struct{ fakeKey }

func (*enrollFails) Enroll(context.Context, [][32]byte) ([][]byte, error) {
	return nil, errors.New("touch timed out")
}

func TestSlotManagement(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	m := make(model, testSectors*SectorSize)
	put(t, c, m, 0, rnd(100))
	// Remove the recovery slot: the code stops working on the CURRENT image.
	var rcSlot int = -1
	salt := make([]byte, format.SaltSize)
	f.ReadAt(salt, 0)
	rc, _ := RecoveryFactor([]byte(code))
	for i := 0; i < format.NumSlots; i++ {
		b := make([]byte, format.SlotSize)
		f.ReadAt(b, int64(format.SlotsOff+i*format.SlotSize))
		if _, err := format.OpenWrap(&rc.KEK, i, b); err == nil {
			rcSlot = i
		}
	}
	if rcSlot < 0 {
		t.Fatal("recovery slot not found")
	}
	old := f.clone() // a copy taken before the removal
	if err := c.RemoveSlot(rcSlot); err != nil {
		t.Fatal(err)
	}
	// Removing a free slot scrubs it again and records nothing.
	epoch := c.Info().Epoch
	if err := c.RemoveSlot(rcSlot); err != nil || c.Info().Epoch != epoch {
		t.Fatalf("removing a free slot: %v, epoch %d -> %d", err, epoch, c.Info().Epoch)
	}
	for _, i := range []int{-1, 16, 99} {
		if err := c.RemoveSlot(i); !errors.Is(err, ErrOption) {
			t.Fatalf("slot %d out of range: %v", i, err)
		}
	}
	c.Close()
	if _, err := Open(ctx, f, Unlock{Recovery: []byte(code)}, OpenOptions{}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("removed recovery slot still opens: %v", err)
	}
	reopen(t, f, pwUnlock()).Close()
	// Documented limit (DESIGN 2, R7): the OLD copy still opens with it.
	reopen(t, old, Unlock{Recovery: []byte(code)}).Close()

	// Fill every slot; the 17th is refused.
	c = reopen(t, f, pwUnlock())
	for i := 0; ; i++ {
		k := randomFactor()
		if err := c.AddSlot(k); err != nil {
			if !errors.Is(err, ErrNoSlot) || i != 15 {
				t.Fatalf("after %d adds: %v", i, err)
			}
			break
		}
	}
	if err := c.AddSlot(); !errors.Is(err, ErrOption) {
		t.Fatal("slot with no factors")
	}
	if err := c.AddSlot(Factor{}, Factor{}, Factor{}); !errors.Is(err, ErrOption) {
		t.Fatal("slot with three factors")
	}
	c.Close()
	reopen(t, f, pwUnlock()).Close()
}

func TestBounds(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	size := int64(testSectors * SectorSize)
	if c.Size() != size {
		t.Fatal("size")
	}
	for _, off := range []int64{-1, size, size + 1, 1 << 62} {
		if _, err := c.WriteAt([]byte{1}, off); !errors.Is(err, ErrRange) {
			t.Errorf("write at %d: %v", off, err)
		}
	}
	if _, err := c.WriteAt(make([]byte, 2), size-1); !errors.Is(err, ErrRange) {
		t.Error("write straddling the end")
	}
	if _, err := c.ReadAt([]byte{1}, -1); !errors.Is(err, ErrRange) {
		t.Error("negative read")
	}
	if n, err := c.ReadAt(make([]byte, 1), size); n != 0 || err != io.EOF {
		t.Errorf("read at end: %d %v", n, err)
	}
	if n, err := c.ReadAt(nil, size+10); n != 0 || err != nil {
		t.Errorf("empty read: %d %v", n, err)
	}
	buf := make([]byte, 10)
	if n, err := c.ReadAt(buf, size-4); n != 4 || err != io.EOF {
		t.Errorf("short read at the end: %d %v", n, err)
	}
	if n, err := c.WriteAt(nil, 0); n != 0 || err != nil {
		t.Errorf("empty write: %d %v", n, err)
	}
	// Create refuses nonsense.
	geo, _ := format.NewGeometry(10, 8)
	f := newMem(int(geo.End))
	for _, o := range []CreateOptions{
		{Sectors: 0, Password: []byte("x")},
		{Sectors: merkle.MaxSectors + 1, Password: []byte("x")},
		{Sectors: 10, Password: nil},
		{Sectors: 10, Password: []byte("x"), Policy: 7},
		{Sectors: 10, Password: []byte("x"), Hint: 5},
		{Sectors: 10, JournalEntries: format.MaxJournal + 1, Password: []byte("x")},
	} {
		if _, _, err := Create(f, o); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}

func TestJournalBudgetForcesCommits(t *testing.T) {
	// 200 distinct sectors with a journal of 8 entries: the container must
	// commit on its own, many times, without error.
	c, f, _ := create(t, PolicyAny)
	m := make(model, testSectors*SectorSize)
	for s := 0; s < testSectors; s++ {
		put(t, c, m, s*SectorSize+17, rnd(300))
	}
	if c.Info().Epoch < 20 {
		t.Fatalf("only %d commits for 200 sector writes through an 8-entry journal", c.Info().Epoch)
	}
	m.check(t, c)
	c.Close()
	m.check(t, reopen(t, f, pwUnlock()))
}

// TestCrashAtEveryWrite: cut the power at every single backing write of a
// multi-sector commit. After each cut the container must reopen, verify, and
// hold exactly the old content or exactly the new content, never a mixture.
func TestCrashAtEveryWrite(t *testing.T) {
	// A journal big enough that the update below is ONE transaction: a
	// write that overflows the journal is committed in several, each atomic.
	base, f, _ := createJ(t, PolicyAny, 64)
	before := make(model, testSectors*SectorSize)
	put(t, base, before, 0, rnd(20000))
	put(t, base, before, 150*4096, rnd(5000))
	if err := base.Sync(); err != nil {
		t.Fatal(err)
	}
	after := append(model(nil), before...)
	update := func(c *Container, m model) {
		put(t, c, m, 3*4096+100, rnd(9000))
		put(t, c, m, 70*4096, rnd(4096))
		put(t, c, m, 150*4096+1, rnd(10))
	}
	// Learn how many writes the commit makes.
	probe := f.clone()
	pc := reopen(t, probe, pwUnlock())
	update(pc, append(model(nil), before...))
	w0 := probe.writes
	if err := pc.Sync(); err != nil {
		t.Fatal(err)
	}
	total := probe.writes - w0
	if total < 8 {
		t.Fatalf("suspiciously few writes in a commit: %d", total)
	}

	var sawOld, sawNew int
	for cut := 0; cut <= total; cut++ {
		img := f.clone()
		c := reopen(t, img, pwUnlock())
		m := append(model(nil), before...)
		update(c, m)
		after = m
		img.failAfter = img.writes + cut
		err := c.Sync()
		if cut == total && err != nil {
			t.Fatalf("complete commit failed: %v", err)
		}
		if cut < total {
			if err == nil {
				t.Fatalf("cut %d: sync survived a power cut", cut)
			}
			if _, err := c.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrBroken) {
				t.Fatalf("cut %d: container usable after a failed commit: %v", cut, err)
			}
		}
		img.failAfter = -1
		r := reopen(t, img, pwUnlock())
		if n, err := r.Verify(); err != nil || n != testSectors {
			t.Fatalf("cut %d: verify %v", cut, err)
		}
		got := make([]byte, len(before))
		r.ReadAt(got, 0)
		switch {
		case bytes.Equal(got, before):
			sawOld++
		case bytes.Equal(got, after):
			sawNew++
		default:
			t.Fatalf("cut %d: content is neither the old nor the new state", cut)
		}
		r.Close()
	}
	if sawOld == 0 || sawNew == 0 {
		t.Fatalf("expected both outcomes across cuts, old=%d new=%d", sawOld, sawNew)
	}
}

// TestJournalReplayAfterCrashBeforeApply: a transaction committed to the
// journal but not applied is replayed on open.
func TestJournalReplay(t *testing.T) {
	base, f, _ := create(t, PolicyAny)
	m := make(model, testSectors*SectorSize)
	put(t, base, m, 0, rnd(5000))
	base.Sync()
	var replayed bool
	for cut := 1; cut < 40 && !replayed; cut++ {
		img := f.clone()
		c := reopen(t, img, pwUnlock())
		m2 := append(model(nil), m...)
		put(t, c, m2, 8192, rnd(6000))
		img.failAfter = img.writes + cut
		c.Sync()
		img.failAfter = -1
		r := reopen(t, img, pwUnlock())
		if r.Info().ReplayedTransaction {
			replayed = true
			m2.check(t, r) // the journal made the commit whole
		}
	}
	if !replayed {
		t.Fatal("no crash point exercised journal replay")
	}
}

// TestOldJournalIsNotReplayed: a genuine old transaction put back into the
// journal area after later commits must not move the container (R1).
func TestOldJournalIsNotReplayed(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	geo, _ := format.NewGeometry(testSectors, testJournal)
	m := make(model, testSectors*SectorSize)
	put(t, c, m, 0, rnd(5000))
	c.Sync()
	oldJournal := append([]byte(nil), f.b[geo.JournalOff:geo.MetaOff]...)
	put(t, c, m, 0, rnd(5000))
	put(t, c, m, 90000, rnd(100))
	c.Sync()
	c.Close()
	copy(f.b[geo.JournalOff:], oldJournal)
	r := reopen(t, f, pwUnlock())
	if r.Info().ReplayedTransaction {
		t.Fatal("an old transaction was replayed")
	}
	m.check(t, r)
}

func TestTamperDetected(t *testing.T) {
	c, f, code := create(t, PolicyAny)
	geo, _ := format.NewGeometry(testSectors, testJournal)
	m := make(model, testSectors*SectorSize)
	put(t, c, m, 0, rnd(100000))
	c.Close()

	flip := func(off uint64) *memFile {
		img := f.clone()
		img.b[off] ^= 1
		return img
	}
	// A data sector.
	img := flip(geo.DataOff + 3*4096 + 17)
	r := reopen(t, img, pwUnlock())
	if _, err := r.ReadAt(make([]byte, 4096), 3*4096); !errors.Is(err, ErrSector) {
		t.Fatalf("sector flip: %v", err)
	}
	if _, err := r.Verify(); !errors.Is(err, ErrSector) {
		t.Fatalf("verify missed a sector flip: %v", err)
	}
	// Other sectors still read: damage is local.
	if _, err := r.ReadAt(make([]byte, 4096), 5*4096); err != nil {
		t.Fatalf("neighbour: %v", err)
	}
	// A metadata block.
	r = reopen(t, flip(geo.MetaOff+10), pwUnlock())
	if _, err := r.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("metadata flip: %v", err)
	}
	// A Merkle node: the written metadata blocks hang under node 0.
	r = reopen(t, flip(geo.TreeOff+5), pwUnlock())
	if _, err := r.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("node flip: %v", err)
	}
	// Writing over a tampered tree is refused too.
	if _, err := r.WriteAt([]byte{1}, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("write over a tampered node: %v", err)
	}
	// A keyslot: the factor of that slot stops working. Every used slot is
	// tried, so flip each of the 16 and count how many break an unlock.
	broken := 0
	for i := 0; i < format.NumSlots; i++ {
		img := flip(uint64(format.SlotsOff + i*format.SlotSize + 100))
		okPW := func() bool { _, err := Open(ctx, img, pwUnlock(), OpenOptions{}); return err == nil }()
		okRC := func() bool {
			_, err := Open(ctx, img, Unlock{Recovery: []byte(code)}, OpenOptions{})
			return err == nil
		}()
		if !okPW || !okRC {
			broken++
			if !okPW && !okRC {
				t.Fatal("one flipped byte broke two independent slots")
			}
		}
	}
	if broken != 2 {
		t.Fatalf("expected exactly the 2 used slots to matter, got %d", broken)
	}
	// Headers: one copy damaged falls back to the other (and the journal
	// brings it forward); both damaged is a refusal, not a guess.
	both := f.clone()
	both.b[geo.HdrA+50] ^= 1
	both.b[geo.HdrB+50] ^= 1
	if _, err := Open(ctx, both, pwUnlock(), OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("both headers damaged: %v", err)
	}
	one := f.clone()
	one.b[geo.Header(reopen(t, f.clone(), pwUnlock()).Info().Epoch)+50] ^= 1
	r = reopen(t, one, pwUnlock())
	m.check(t, r)
}

// TestForgedHeaderBomb: a header sealed with the right keys but claiming a
// 2^40-sector container in a small file is refused before any allocation.
func TestForgedHeaderBomb(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	c.body.Sectors = merkle.MaxSectors
	c.body.Epoch += 11 // odd: the forgery lands in copy B, the genuine epoch 0 stays in A
	if err := c.writeHeader(); err != nil {
		t.Fatal(err)
	}
	// The forged copy fails to parse; the genuine older copy still wins.
	r := reopen(t, f, pwUnlock())
	if r.Info().Sectors != testSectors {
		t.Fatal("forged geometry accepted")
	}
	// With both copies forged there is nothing left to open.
	c.body.Epoch++ // even: now copy A is forged as well
	c.writeHeader()
	if _, err := Open(ctx, f, pwUnlock(), OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("%v", err)
	}
}

// ---- rollback counter ------------------------------------------------------

type fakeCounter struct {
	handle  uint32
	name    []byte
	v       uint64
	failInc bool
}

func (c *fakeCounter) Handle() uint32        { return c.handle }
func (c *fakeCounter) Name() []byte          { return c.name }
func (c *fakeCounter) Read() (uint64, error) { return c.v, nil }
func (c *fakeCounter) Increment() error {
	if c.failInc {
		return errors.New("tpm unavailable")
	}
	c.v++
	return nil
}

func TestRollbackCounter(t *testing.T) {
	ctr := &fakeCounter{handle: 0x01800001, name: bytes.Repeat([]byte{9}, 34), v: 1000}
	geo, _ := format.NewGeometry(testSectors, testJournal)
	f := newMem(int(geo.End))
	c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal,
		Password: []byte("pw"), Counter: ctr})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Info().RollbackProtected || ctr.v != 1001 {
		t.Fatalf("create: %+v counter %d", c.Info(), ctr.v)
	}
	m := make(model, testSectors*SectorSize)
	put(t, c, m, 0, rnd(1000))
	c.Close()
	u := Unlock{Password: []byte("pw")}
	op := OpenOptions{Counter: ctr}

	// Session 1.
	r, err := Open(ctx, f, u, op)
	if err != nil {
		t.Fatal(err)
	}
	m.check(t, r)
	r.Close()
	snapshot := f.clone() // the container as of the end of session 1
	// Session 2 (the legitimate one) moves the counter on.
	r, err = Open(ctx, f, u, op)
	if err != nil {
		t.Fatal(err)
	}
	put(t, r, m, 0, rnd(1000))
	r.Close()

	// Restoring the older image is refused...
	if _, err := Open(ctx, snapshot, u, op); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback accepted: %v", err)
	}
	// Wrong or missing counter.
	for name, o := range map[string]OpenOptions{
		"none":        {},
		"other name":  {Counter: &fakeCounter{handle: 0x01800001, name: []byte("x"), v: ctr.v}},
		"other index": {Counter: &fakeCounter{handle: 5, name: ctr.name, v: ctr.v}},
	} {
		if _, err := Open(ctx, f, u, o); !errors.Is(err, ErrCounter) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A crash between the header write and the increment resolves by
	// incrementing (b == c+1), and the container opens.
	ctr.failInc = true
	if _, err := Open(ctx, f, u, op); err == nil {
		t.Fatal("increment failure swallowed")
	}
	ctr.failInc = false
	r, err = Open(ctx, f, u, op)
	if err != nil {
		t.Fatalf("resolve b == c+1: %v", err)
	}
	r.Close()
	// Counter reads go through errors, too.
	if _, err := Open(ctx, f, u, OpenOptions{Counter: &brokenCounter{*ctr}}); err == nil {
		t.Fatal("counter read error swallowed")
	}
	// The owner may restore the older image on purpose, loudly. This
	// rebinds the header to the counter and consumes the counter, so it
	// comes last.
	r, err = Open(ctx, snapshot, u, OpenOptions{Counter: ctr, AcceptRollback: true})
	if err != nil {
		t.Fatalf("explicit accept: %v", err)
	}
	r.Close()
	// Create with a failing counter.
	failing := []Counter{&fakeCounter{failInc: true}, &brokenCounter{}}
	for _, bc := range failing {
		opts := CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"), Counter: bc}
		if _, _, err := Create(newMem(int(geo.End)), opts); err == nil {
			t.Fatal("counter failure at create swallowed")
		}
	}
}

type brokenCounter struct {
	fakeCounter
}

func (b *brokenCounter) Read() (uint64, error) { return 0, errors.New("tpm read failed") }

func TestNoCounterIsStatedPlainly(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	c.Close()
	r := reopen(t, f, pwUnlock())
	if r.Info().RollbackProtected {
		t.Fatal("a container with no counter claims rollback protection")
	}
	// A counter handed to a container that does not use one is refused, not
	// ignored and not silently bound (#66).
	if _, err := Open(ctx, f, pwUnlock(), OpenOptions{Counter: &fakeCounter{}}); !errors.Is(err, ErrCounterRequired) {
		t.Fatalf("%v", err)
	}
}

func TestFileBacking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.theca")
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	b := FileBacking{fh}
	c, _, err := Create(b, CreateOptions{Sectors: 100, JournalEntries: 8, Password: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteAt([]byte("hello"), 4096); err != nil {
		t.Fatal(err)
	}
	c.Close()
	st, _ := fh.Stat()
	if st.Size()%(1<<20) != 0 || st.Size() == 0 {
		t.Fatalf("file size %d is not a whole number of MiB", st.Size())
	}
	r, err := Open(ctx, b, Unlock{Password: []byte("pw")}, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	r.ReadAt(got, 4096)
	if string(got) != "hello" {
		t.Fatalf("%q", got)
	}
	if _, err := (FileBacking{fh}).Size(); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	if _, err := (FileBacking{fh}).Size(); err == nil {
		t.Fatal("size of a closed file")
	}
	// A pre-grown file is truncated to the container's size.
	big := FileBacking{mustFile(t, 5<<20)}
	if _, _, err := Create(big, CreateOptions{Sectors: 10, JournalEntries: 8, Password: []byte("pw")}); err != nil {
		t.Fatal(err)
	}
	if sz, _ := big.Size(); sz != 1<<20 {
		t.Fatalf("not truncated: %d", sz)
	}
}

func mustFile(t *testing.T, n int64) *os.File {
	f, err := os.Create(filepath.Join(t.TempDir(), "big"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	f.Truncate(n)
	return f
}

func TestBackingFailures(t *testing.T) {
	// A write error anywhere in Create is reported.
	geo, _ := format.NewGeometry(testSectors, testJournal)
	for cut := 0; cut < 5; cut++ { // fill, salt, two slots, header
		f := newMem(int(geo.End))
		f.failAfter = cut
		if _, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")}); err == nil {
			t.Errorf("create survived a cut at write %d", cut)
		}
	}
	f := newMem(int(geo.End))
	f.syncFail = true
	if _, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")}); err == nil {
		t.Error("sync failure at create swallowed")
	}
	// After a failed commit the container refuses everything.
	c, f2, _ := create(t, PolicyAny)
	c.WriteAt([]byte("x"), 0)
	f2.syncFail = true
	if err := c.Sync(); err == nil {
		t.Fatal("sync error swallowed")
	}
	f2.syncFail = false
	for _, err := range []error{
		func() error { _, e := c.ReadAt(make([]byte, 1), 0); return e }(),
		func() error { _, e := c.WriteAt([]byte{1}, 0); return e }(),
		c.Sync(), c.AddSlot(Factor{}), c.RemoveSlot(0),
		func() error { _, e := c.Verify(); return e }(),
	} {
		if !errors.Is(err, ErrBroken) {
			t.Errorf("%v", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Errorf("close of a broken container: %v", err)
	}
}

func TestFillRandom(t *testing.T) {
	f := newMem(3<<20 + 5)
	if err := fillRandom(f, uint64(len(f.b)), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(f.b[:1<<20], f.b[1<<20:2<<20]) {
		t.Fatal("blocks repeat")
	}
	if err := fillRandom(f, 10, failReader{}); err == nil {
		t.Fatal("rng failure swallowed")
	}
	f.failAfter = 0
	if err := fillRandom(f, 10, rand.Reader); err == nil {
		t.Fatal("write failure swallowed")
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRandomnessFailures(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	// Fail the n-th byte-range read from the source, for every n, during
	// Create: nothing may succeed with a broken source.
	for n := 0; n < 12; n++ {
		l := &limitedRand{n: n}
		_, _, err := Create(newMem(int(geo.End)), CreateOptions{Sectors: testSectors,
			JournalEntries: testJournal, Password: []byte("pw"), Rand: l})
		if err == nil {
			t.Errorf("create succeeded with a source failing after %d reads", n)
		}
	}
	c, _, _ := create(t, PolicyAny)
	c.rng = failReader{}
	if _, err := c.WriteAt([]byte{1}, 0); err == nil {
		t.Error("write with a failing source")
	}
	if err := c.AddSlot(Factor{Kind: "x"}); err == nil {
		t.Error("slot with a failing source")
	}
	if err := c.EnrollFIDO2(ctx, newKey(), Factor{Kind: "pw"}); err == nil {
		t.Error("enrolment with a failing source")
	}
	if _, err := c.freeSlot(); err == nil {
		t.Error("freeSlot with a failing source")
	}
}

type limitedRand struct {
	n     int
	fired bool
}

func (l *limitedRand) Read(p []byte) (int, error) {
	if l.n <= 0 {
		l.fired = true
		return 0, io.ErrUnexpectedEOF
	}
	l.n--
	return rand.Read(p)
}

func TestUnbiasedSlotChoice(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	seen := map[int]int{}
	for i := 0; i < 3000; i++ {
		s, err := c.freeSlot()
		if err != nil {
			t.Fatal(err)
		}
		seen[s]++
	}
	if len(seen) != format.NumSlots-2 {
		t.Fatalf("%d distinct free slots chosen, want %d", len(seen), format.NumSlots-2)
	}
	for s, n := range seen {
		if c.body.SlotsUsed&(1<<s) != 0 {
			t.Fatalf("picked a used slot %d", s)
		}
		if n < 100 || n > 400 { // mean 214
			t.Errorf("slot %d chosen %d of 3000 times", s, n)
		}
	}
}

// faultFile fails exactly the n-th backing operation (read, write, sync or
// size query), numbering from zero.
type faultFile struct {
	*memFile
	n, ops int
	fired  bool
}

func (f *faultFile) hit() bool {
	i := f.ops
	f.ops++
	if i == f.n {
		f.fired = true
		return true
	}
	return false
}

func (f *faultFile) ReadAt(p []byte, off int64) (int, error) {
	if f.hit() {
		return 0, errCut
	}
	return f.memFile.ReadAt(p, off)
}

func (f *faultFile) WriteAt(p []byte, off int64) (int, error) {
	if f.hit() {
		return 0, errCut
	}
	return f.memFile.WriteAt(p, off)
}

func (f *faultFile) Sync() error {
	if f.hit() {
		return errCut
	}
	return f.memFile.Sync()
}

func (f *faultFile) Size() (int64, error) {
	if f.hit() {
		return 0, errCut
	}
	return f.memFile.Size()
}

// sweep runs scenario with a fault at operation 0, 1, 2, ... until a run
// finishes without the fault firing. Every run where it fired must return an
// error: no I/O failure may be swallowed.
func sweep(t *testing.T, name string, image func() *memFile, scenario func(Backing) error) {
	t.Helper()
	for n := 0; n < 100000; n++ {
		ff := &faultFile{memFile: image(), n: n}
		err := scenario(ff)
		if !ff.fired {
			if err != nil {
				t.Fatalf("%s: clean run failed: %v", name, err)
			}
			return
		}
		if err == nil {
			t.Fatalf("%s: a fault at operation %d was swallowed", name, n)
		}
	}
	t.Fatalf("%s: scenario never finished", name)
}

func TestIOErrorsAreNeverSwallowed(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	fresh := func() *memFile { return newMem(int(geo.End)) }

	sweep(t, "create+use", fresh, func(f Backing) error {
		c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"), Policy: PolicyTwoOfThree})
		if err != nil {
			return err
		}
		if _, err := c.WriteAt(rnd(9000), 100); err != nil {
			return err
		}
		if err := c.AddSlot(randomFactor()); err != nil {
			return err
		}
		if err := c.EnrollFIDO2(ctx, newKey(), randomFactor()); err != nil {
			return err
		}
		if err := c.RemoveSlot(0); err != nil {
			// slot 0 may be free: that is a usage error, not an I/O error
			if errors.Is(err, ErrOption) {
				return c.Sync()
			}
			return err
		}
		if _, err := c.Verify(); err != nil {
			return err
		}
		if err := c.Sync(); err != nil {
			return err
		}
		return c.Close()
	})

	// A used image, opened, read, verified.
	c, base, _ := create(t, PolicyAny)
	c.WriteAt(rnd(20000), 3000)
	c.Close()
	sweep(t, "open+read", base.clone, func(f Backing) error {
		c, err := Open(ctx, f, pwUnlock(), OpenOptions{})
		if err != nil {
			return err
		}
		if _, err := c.ReadAt(make([]byte, 8000), 2500); err != nil {
			return err
		}
		_, err = c.Verify()
		return err
	})

	// An image that needs journal replay.
	cj, jbase, _ := create(t, PolicyAny)
	cj.WriteAt(rnd(100), 0)
	cj.Sync()
	var crashed *memFile
	for cut := 1; cut < 60 && crashed == nil; cut++ {
		img := jbase.clone()
		cc := reopen(t, img, pwUnlock())
		cc.WriteAt(rnd(5000), 8192)
		img.failAfter = img.writes + cut
		cc.Sync()
		img.failAfter = -1
		if probe := reopen(t, img.clone(), pwUnlock()); probe.Info().ReplayedTransaction {
			crashed = img
		}
	}
	if crashed == nil {
		t.Fatal("no replay image")
	}
	sweep(t, "replay", crashed.clone, func(f Backing) error {
		_, err := Open(ctx, f, pwUnlock(), OpenOptions{})
		return err
	})

	// A container with a counter.
	ctr := &fakeCounter{handle: 1, name: []byte("n"), v: 5}
	cc, _, err := Create(fresh(), CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"), Counter: ctr})
	if err != nil {
		t.Fatal(err)
	}
	_ = cc
	cf := newMem(int(geo.End))
	ctr2 := &fakeCounter{handle: 1, name: []byte("n"), v: 5}
	cc2, _, _ := Create(cf, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw"), Counter: ctr2})
	cc2.Close()
	sweep(t, "counter", func() *memFile { ctr2.v = 6; return cf.clone() }, func(f Backing) error {
		_, err := Open(ctx, f, Unlock{Password: []byte("pw")}, OpenOptions{Counter: &fakeCounter{handle: 1, name: []byte("n"), v: 6}})
		return err
	})
}

// Truncate lets faultFile act like an *os.File that is larger than needed.
func (f *faultFile) Truncate(n int64) error {
	if f.hit() {
		return errCut
	}
	f.b = f.b[:n]
	return nil
}

func usedSlot(c *Container) int {
	for i := 0; i < format.NumSlots; i++ {
		if c.body.SlotsUsed&(1<<i) != 0 {
			return i
		}
	}
	return -1
}

func TestIOErrorsInSlotsAndTruncate(t *testing.T) {
	geo, _ := format.NewGeometry(testSectors, testJournal)
	big := func() *memFile { return newMem(int(geo.End) + 3<<20) }
	sweep(t, "create (oversized file) and manage slots", big, func(f Backing) error {
		c, _, err := Create(f, CreateOptions{Sectors: testSectors, JournalEntries: testJournal, Password: []byte("pw")})
		if err != nil {
			return err
		}
		if sz, _ := f.Size(); sz != int64(geo.End) {
			return errors.New("not truncated")
		}
		if _, err := c.WriteAt(rnd(40000), 1000); err != nil { // 10 sectors, journal of 8: budget commits
			return err
		}
		if err := c.EnrollFIDO2(ctx, newKey(), randomFactor()); err != nil {
			return err
		}
		if err := c.RemoveSlot(usedSlot(c)); err != nil {
			return err
		}
		if _, err := c.ReadAt(make([]byte, 5000), 2000); err != nil {
			return err
		}
		return c.Close()
	})
}

// rngSweep fails the n-th read from the random source, for every n.
func TestRandomSourceFailuresAreNeverSwallowed(t *testing.T) {
	for n := 0; n < 200; n++ {
		c, _, _ := create(t, PolicyAny)
		l := &limitedRand{n: n}
		c.rng = l
		var err error
		steps := []func() error{
			func() error { _, e := c.WriteAt(rnd(9000), 50); return e },
			func() error { return c.AddSlot(randomFactor()) },
			func() error { return c.EnrollFIDO2(ctx, newKey(), randomFactor()) },
			func() error { return c.RemoveSlot(usedSlot(c)) },
			func() error { return c.Sync() },
		}
		for _, s := range steps {
			if err = s(); err != nil {
				break
			}
		}
		if !l.fired && err == nil {
			return // the source was never exhausted: scenario fully covered
		}
		if err == nil {
			t.Fatalf("n=%d: a failing random source was swallowed", n)
		}
	}
}

func TestEnrollRoomRefusals(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	for c.Info().SlotsUsed < format.NumSlots-1 {
		if err := c.AddSlot(randomFactor()); err != nil {
			t.Fatal(err)
		}
	}
	// One free slot left: a key paired with two partners needs two. The
	// enrolment is refused whole, before the key is touched, and the last
	// slot stays free.
	k := newKey()
	pw, rc := Factor{Kind: "pw", KEK: [32]byte{1}}, Factor{Kind: "rc", KEK: [32]byte{2}}
	if err := c.EnrollFIDO2(ctx, k, pw, rc); !errors.Is(err, ErrNoSlot) || k.enrolls != 0 {
		t.Fatalf("enrolment without room: %v after %d touches", err, k.enrolls)
	}
	if c.Info().SlotsUsed != format.NumSlots-1 {
		t.Fatalf("a refused enrolment used slots: %d", c.Info().SlotsUsed)
	}
	// One partner fits.
	if err := c.EnrollFIDO2(ctx, k, pw); err != nil {
		t.Fatal(err)
	}
	// Now there is none at all.
	if err := c.EnrollFIDO2(ctx, k, pw); !errors.Is(err, ErrNoSlot) {
		t.Fatalf("%v", err)
	}
	c.Close()
	if err := c.EnrollFIDO2(ctx, k, pw); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	if err := c.AddSlot(Factor{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	if err := c.RemoveSlot(0); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	if _, err := c.WriteAt([]byte{1}, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	if err := c.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
	if _, err := c.Verify(); !errors.Is(err, ErrClosed) {
		t.Fatalf("%v", err)
	}
}

func TestApplyRangeChecks(t *testing.T) {
	c, _, _ := create(t, PolicyAny)
	blk := make([]byte, 4096)
	for _, r := range []journal.Record{
		{Area: journal.AreaData, Index: testSectors, Data: blk},
		{Area: journal.AreaMeta, Index: c.geo.Shape.MetaBlocks, Data: blk},
		{Area: journal.AreaNode, Index: c.geo.Shape.NodeCount(), Data: blk},
		{Area: journal.AreaData, Index: ^uint64(0), Data: blk},
	} {
		if err := c.apply(&journal.Tx{Records: []journal.Record{r}}); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%+v: %v", r.Area, err)
		}
	}
}

// TestSetMetaOverTamperedTree: the path check in SetMeta is reachable when a
// metadata block is cached but the tree above it is not.
func TestSetMetaOverTamperedTree(t *testing.T) {
	c, f, _ := create(t, PolicyAny)
	geo, _ := format.NewGeometry(testSectors, testJournal)
	c.WriteAt(rnd(100), 0)
	c.Close()
	img := f.clone()
	img.b[geo.TreeOff+9] ^= 1
	r := reopen(t, img, pwUnlock())
	blk, _ := r.freshMeta(0)
	r.meta.Put(0, blk)
	if _, err := r.WriteAt([]byte{1}, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("%v", err)
	}
	// A whole-sector write skips the read-modify-write and meets the
	// tampered tree in writeSector itself.
	r2 := reopen(t, img.clone(), pwUnlock())
	if _, err := r2.WriteAt(make([]byte, SectorSize), 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("whole-sector write over a tampered tree: %v", err)
	}
}

func TestRecoveryAndCounterErrorPaths(t *testing.T) {
	// A replay whose commit root does not match what the replay leaves on
	// disk is refused (the writer-bug case of DESIGN 5.3).
	c, f, _ := create(t, PolicyAny)
	c.WriteAt(rnd(100), 0)
	c.Sync()
	// Build a transaction for epoch+1 with a wrong root and put it in the
	// journal with the right keys.
	tx := &journal.Tx{Epoch: c.body.Epoch + 1, Root: [32]byte{1, 2, 3}}
	jr := region{f, int64(c.geo.JournalOff)}
	if err := journal.Write(c.k, jr, c.body.JournalEntries, tx, rand.Reader, f.Sync); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, f, pwUnlock(), OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched replay root: %v", err)
	}
	// A replay record with an out-of-range index is refused.
	c2, f2, _ := create(t, PolicyAny)
	tx2 := &journal.Tx{Epoch: 1, Records: []journal.Record{{Area: journal.AreaData, Index: 1 << 30, Data: make([]byte, 4096)}}}
	if err := journal.Write(c2.k, region{f2, int64(c2.geo.JournalOff)}, c2.body.JournalEntries, tx2, rand.Reader, f2.Sync); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, f2, pwUnlock(), OpenOptions{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("out-of-range replay index: %v", err)
	}
	// Unreadable header copies surface the I/O error.
	short := newMem(int(format.HdrOff + 100))
	if _, err := Open(ctx, short, pwUnlock(), OpenOptions{}); err == nil {
		t.Fatal("short file opened")
	}
}

// FuzzOpenMutated flips one byte of a valid image: Open and everything after
// it must not panic, whatever the byte is, and may only succeed with a
// consistent container.
func FuzzOpenMutated(f *testing.F) {
	c, img, _ := create(f, PolicyAny)
	c.WriteAt(bytes.Repeat([]byte{7}, 9000), 100)
	c.Close()
	f.Add(uint32(0), byte(1))
	f.Add(uint32(format.HdrOff+10), byte(0x80))
	f.Add(uint32(format.SlotsOff+3000), byte(0xff))
	f.Fuzz(func(t *testing.T, off uint32, x byte) {
		m := img.clone()
		m.b[int(off)%len(m.b)] ^= x
		r, err := Open(ctx, m, pwUnlock(), OpenOptions{})
		if err != nil {
			return
		}
		r.Verify()
		r.ReadAt(make([]byte, 9000), 50)
	})
}
