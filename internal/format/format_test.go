package format

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/go-theca/theca/internal/journal"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/ta1"
)

func keys(t testing.TB) *ta1.Keys {
	k, err := ta1.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGeometry(t *testing.T) {
	g, err := NewGeometry(1000, 16)
	if err != nil {
		t.Fatal(err)
	}
	if g.HdrA != 32800 || g.HdrB != 32800+8192 {
		t.Fatalf("headers at %d, %d", g.HdrA, g.HdrB)
	}
	for _, o := range []uint64{g.JournalOff, g.MetaOff, g.TreeOff, g.DataOff} {
		if o%Align != 0 {
			t.Fatalf("offset %d not aligned", o)
		}
	}
	if !(g.HdrB+HeaderSize <= g.JournalOff && g.JournalOff+16*journal.EntrySize <= g.MetaOff &&
		g.MetaOff+g.Shape.MetaBlocks*4096 == g.TreeOff && g.TreeOff+g.Shape.NodeCount()*4096 == g.DataOff &&
		g.DataOff+1000*4096 <= g.End && g.End%TailAlign == 0 && g.End-g.DataOff-1000*4096 < TailAlign) {
		t.Fatalf("areas overlap or leave a gap: %+v", g)
	}
	if g.Header(0) != g.HdrA || g.Header(1) != g.HdrB || g.Header(2) != g.HdrA {
		t.Fatal("header copy selection")
	}
	// bounds
	if _, err := NewGeometry(0, 16); !errors.Is(err, ErrGeometry) {
		t.Fatal(err)
	}
	if _, err := NewGeometry(1<<40+1, 16); !errors.Is(err, ErrGeometry) {
		t.Fatal(err)
	}
	if _, err := NewGeometry(1, 3); !errors.Is(err, ErrGeometry) { // below MinJournal
		t.Fatal(err)
	}
	if _, err := NewGeometry(1, MaxJournal+1); !errors.Is(err, ErrGeometry) {
		t.Fatal(err)
	}
	if _, err := NewGeometry(1, ^uint32(0)); !errors.Is(err, ErrGeometry) {
		t.Fatal(err)
	}
	// 2^40 sectors is 4 PiB: allowed, and computed without overflow.
	g, err = NewGeometry(1<<40, 64)
	if err != nil || g.End < 1<<52 || g.End > 1<<62 {
		t.Fatalf("2^40 sectors: %v %d", err, g.End)
	}
	if MinJournal(g.Shape) != uint32(g.Shape.Levels())+4 {
		t.Fatal("MinJournal")
	}
}

func sampleBody() *Body {
	b := &Body{Sectors: 1000, JournalEntries: 16, Epoch: 7, SlotsUsed: 0b101}
	rand.Read(b.CID[:])
	rand.Read(b.Root[:])
	return b
}

func TestBodyRoundTrip(t *testing.T) {
	for _, withCtr := range []bool{false, true} {
		b := sampleBody()
		if withCtr {
			b.Counter = &Counter{Handle: 0x01800001, Name: bytes.Repeat([]byte{0xab}, 34), Bound: 1 << 40}
		}
		p := b.Marshal()
		if len(p) != BodySize || BodySize != 8120 {
			t.Fatalf("body is %d bytes", len(p))
		}
		got, g, err := ParseBody(p, 1<<40)
		if err != nil {
			t.Fatal(err)
		}
		if g.Sectors != 1000 || got.CID != b.CID || got.Epoch != 7 || got.Root != b.Root || got.SlotsUsed != 5 {
			t.Fatalf("round trip: %+v", got)
		}
		if withCtr && (got.Counter == nil || got.Counter.Handle != 0x01800001 ||
			!bytes.Equal(got.Counter.Name, b.Counter.Name) || got.Counter.Bound != 1<<40) {
			t.Fatalf("counter: %+v", got.Counter)
		}
		if !withCtr && got.Counter != nil {
			t.Fatal("phantom counter")
		}
	}
}

func TestParseBodyRefusals(t *testing.T) {
	good := sampleBody().Marshal()
	mut := func(f func(p []byte)) []byte {
		p := append([]byte(nil), good...)
		f(p)
		return p
	}
	g, _ := NewGeometry(1000, 16)
	cases := map[string][]byte{
		"short":            good[:100],
		"version":          mut(func(p []byte) { p[0] = 2 }),
		"suite":            mut(func(p []byte) { p[1] = 9 }),
		"unknown flag":     mut(func(p []byte) { p[2] = 0x80 }),
		"reserved byte":    mut(func(p []byte) { p[3] = 1 }),
		"zero sectors":     mut(func(p []byte) { clear(p[20:28]) }),
		"huge sectors":     mut(func(p []byte) { p[27] = 0xff }),
		"journal too big":  mut(func(p []byte) { p[31] = 0xff }),
		"padding":          mut(func(p []byte) { p[BodySize-1] = 1 }),
		"counter no flag":  mut(func(p []byte) { p[74] = 1 }),
		"counter bound":    mut(func(p []byte) { p[143] = 1 }),
		"flag, empty name": mut(func(p []byte) { p[2] = flagCtr }),
		"flag, long name":  mut(func(p []byte) { p[2], p[78] = flagCtr, 65 }),
	}
	for name, p := range cases {
		if _, _, err := ParseBody(p, 1<<50); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A header that claims more than the file holds.
	if _, _, err := ParseBody(good, g.End-1); !errors.Is(err, ErrBody) {
		t.Errorf("oversize header: %v", err)
	}
	if _, _, err := ParseBody(good, g.End); err != nil {
		t.Errorf("exact size refused: %v", err)
	}
}

func TestHeaderSealTamper(t *testing.T) {
	k := keys(t)
	blob, err := SealHeader(k, sampleBody(), rand.Reader)
	if err != nil || len(blob) != HeaderSize {
		t.Fatalf("%d %v", len(blob), err)
	}
	if _, _, err := OpenHeader(k, blob, 1<<40); err != nil {
		t.Fatal(err)
	}
	// Every byte class of the header: seed, ciphertext (first, middle, last),
	// tag. No byte is outside the tag.
	for _, pos := range []int{0, 39, 40, 100, 4000, HeaderSize - 33, HeaderSize - 32, HeaderSize - 1} {
		b := append([]byte(nil), blob...)
		b[pos] ^= 1
		if _, _, err := OpenHeader(k, b, 1<<40); !errors.Is(err, ta1.ErrAuth) {
			t.Fatalf("byte %d: %v", pos, err)
		}
	}
	if _, _, err := OpenHeader(keys(t), blob, 1<<40); !errors.Is(err, ta1.ErrAuth) {
		t.Fatal("wrong key")
	}
}

func TestWrapSlots(t *testing.T) {
	ms := keys(t)
	kek := kdf.KEK([]byte("secret"), "pw")
	slot, err := SealWrap(ms, &kek, 3, rand.Reader)
	if err != nil || len(slot) != SlotSize {
		t.Fatalf("%d %v", len(slot), err)
	}
	got, err := OpenWrap(&kek, 3, slot)
	if err != nil || !bytes.Equal(got.Bytes(), ms.Bytes()) {
		t.Fatalf("%v", err)
	}
	// Wrong KEK, wrong index (a slot moved to another position), any byte.
	other := kdf.KEK([]byte("other"), "pw")
	if _, err := OpenWrap(&other, 3, slot); !errors.Is(err, ta1.ErrAuth) {
		t.Fatal("wrong kek")
	}
	if _, err := OpenWrap(&kek, 4, slot); !errors.Is(err, ta1.ErrAuth) {
		t.Fatal("slot moved to another index")
	}
	for _, pos := range []int{0, 40, 1000, SlotSize - 33, SlotSize - 1} {
		b := append([]byte(nil), slot...)
		b[pos] ^= 1
		if _, err := OpenWrap(&kek, 3, b); !errors.Is(err, ta1.ErrAuth) {
			t.Fatalf("byte %d: %v", pos, err)
		}
	}
	// Random filler never opens.
	junk, _ := RandomSlot(rand.Reader)
	if _, err := OpenWrap(&kek, 0, junk); err == nil {
		t.Fatal("random slot opened")
	}
	for _, f := range []func() error{
		func() error { _, err := SealWrap(ms, &kek, -1, rand.Reader); return err },
		func() error { _, err := SealWrap(ms, &kek, NumSlots, rand.Reader); return err },
		func() error { _, err := OpenWrap(&kek, 0, slot[:10]); return err },
		func() error { _, err := OpenWrap(&kek, 16, slot); return err },
	} {
		if !errors.Is(f(), ErrSlot) {
			t.Fatal("bad input accepted")
		}
	}
}

func TestPairSlotNeedsBothFactors(t *testing.T) {
	ms := keys(t)
	a, b := kdf.KEK([]byte("a"), "pw"), kdf.KEK([]byte("b"), "fido2")
	pair := kdf.Pair(&a, "pw", &b, "fido2")
	slot, _ := SealWrap(ms, &pair, 0, rand.Reader)
	for _, single := range []*[32]byte{&a, &b} {
		if _, err := OpenWrap(single, 0, slot); err == nil {
			t.Fatal("one factor opened a pairwise slot")
		}
	}
	if _, err := OpenWrap(&pair, 0, slot); err != nil {
		t.Fatal(err)
	}
}

type failRand struct{}

func (failRand) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestSlotRandomFailures(t *testing.T) {
	ms := keys(t)
	kek := kdf.KEK([]byte("x"), "pw")
	if _, err := RandomSlot(failRand{}); !errors.Is(err, ta1.ErrNoRand) {
		t.Fatal(err)
	}
	if _, err := SealWrap(ms, &kek, 0, failRand{}); !errors.Is(err, ta1.ErrNoRand) {
		t.Fatal(err)
	}
	loc := &Locator{CredID: []byte{1, 2, 3}}
	if _, err := SealLocator(&kek, loc, failRand{}); !errors.Is(err, ta1.ErrNoRand) {
		t.Fatal(err)
	}
	// second draw (the seed) failing
	if _, err := SealLocator(&kek, loc, &limited{n: 1}); !errors.Is(err, ta1.ErrNoRand) {
		t.Fatal(err)
	}
}

type limited struct{ n int }

func (l *limited) Read(p []byte) (int, error) {
	if l.n == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	l.n--
	return rand.Read(p)
}

func TestLocator(t *testing.T) {
	kek := kdf.KEK([]byte("partner"), "pw")
	loc := &Locator{CredID: bytes.Repeat([]byte{7}, 96), Flags: LocUV | LocPIN2}
	rand.Read(loc.Salt[:])
	blob, err := SealLocator(&kek, loc, rand.Reader)
	if err != nil || len(blob) != SlotSize {
		t.Fatalf("%d %v", len(blob), err)
	}
	got, ok := OpenLocator(&kek, blob)
	if !ok || !bytes.Equal(got.CredID, loc.CredID) || got.Salt != loc.Salt || got.Flags != loc.Flags {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	// Untagged and shapeless: a wrong key ALWAYS yields a valid-looking
	// locator, so no password guess can be filtered without asking the key
	// (review of PR #4). The lengths it yields cover the whole 1..128 range.
	other := kdf.KEK([]byte("other"), "pw")
	lengths := map[int]bool{}
	for i := 0; i < 2000; i++ {
		b, _ := SealLocator(&kek, loc, rand.Reader)
		g, ok := OpenLocator(&other, b)
		if !ok || len(g.CredID) < 1 || len(g.CredID) > MaxCredID || g.Flags&^locMask != 0 {
			t.Fatalf("wrong key did not yield a well-formed locator: %v %+v", ok, g)
		}
		if bytes.Equal(g.CredID, loc.CredID) {
			t.Fatal("wrong key recovered the credential id")
		}
		lengths[len(g.CredID)] = true
	}
	if len(lengths) < 100 {
		t.Fatalf("only %d distinct lengths from a wrong key", len(lengths))
	}
	// The test above only sees what OpenLocator returns; an attacker reads
	// the decrypted bytes. Under the RIGHT key, every bit that is not data
	// must be random: the 6 non-flag bits of the flags byte take both values
	// across sealings (review 2 of PR #4: they were always 0, a 6-bit
	// offline test of every password guess).
	wk := kdf.Keys(&kek)
	orBits, andBits := byte(0), byte(0xff)
	for i := 0; i < 256; i++ {
		b, _ := SealLocator(&kek, loc, rand.Reader)
		plain, err := wk.OpenUntagged(b)
		if err != nil {
			t.Fatal(err)
		}
		fb := plain[1+MaxCredID+32] &^ locMask
		orBits |= fb
		andBits &= fb
		if plain[0]&0x80 != 0 {
			orBits |= 1 // also count the length byte's padding bit
		} else {
			andBits &^= 1
		}
	}
	wk.Zeroize()
	if orBits != 0xff&^locMask|1 || andBits != 0 {
		t.Fatalf("padding bits constant under the right key: or %08b and %08b", orBits, andBits)
	}
	// The length encoding is exact at both ends.
	for _, n := range []int{1, 128} {
		l := &Locator{CredID: bytes.Repeat([]byte{5}, n), Flags: LocPIN2}
		b, err := SealLocator(&kek, l, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if g, ok := OpenLocator(&kek, b); !ok || !bytes.Equal(g.CredID, l.CredID) || g.Flags != LocPIN2 {
			t.Fatalf("length %d did not round trip", n)
		}
	}
	// Refusals.
	for _, l := range []*Locator{
		{CredID: nil}, {CredID: make([]byte, 129)}, {CredID: []byte{1}, Flags: 0x80},
	} {
		if _, err := SealLocator(&kek, l, rand.Reader); !errors.Is(err, ErrSlot) {
			t.Fatalf("%+v: %v", l, err)
		}
	}
	if _, ok := OpenLocator(&kek, blob[:5]); ok {
		t.Fatal("short blob parsed")
	}
	// A wrap slot read as a locator: no panic, and not a usable credential
	// unless it happens to be shaped like one.
	ms := keys(t)
	w, _ := SealWrap(ms, &kek, 0, rand.Reader)
	OpenLocator(&kek, w)
}

func TestRecoveryCode(t *testing.T) {
	raw, printed, err := NewRecoveryCode(rand.Reader)
	if err != nil || len(raw) != 20 {
		t.Fatal(err)
	}
	if len(printed) != 33+8 || strings.Count(printed, "-") != 8 {
		t.Fatalf("printed form %q", printed)
	}
	for _, in := range []string{printed, strings.ToLower(printed), strings.ReplaceAll(printed, "-", " "),
		strings.ReplaceAll(printed, "-", "") + "\n"} {
		got, err := ParseRecoveryCode(in)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%q: %v", in, err)
		}
	}
	plain := strings.ReplaceAll(printed, "-", "")
	// Every single-character substitution and every adjacent transposition
	// of different characters is caught by the check symbol.
	for i := 0; i < len(plain); i++ {
		for _, c := range alphabet {
			if byte(c) == plain[i] {
				continue
			}
			bad := plain[:i] + string(c) + plain[i+1:]
			if _, err := ParseRecoveryCode(bad); err == nil {
				t.Fatalf("substitution at %d to %c accepted", i, c)
			}
		}
	}
	for i := 0; i+1 < 32; i++ {
		d := strings.IndexByte(alphabet, plain[i]) - strings.IndexByte(alphabet, plain[i+1])
		if d == 0 || d == 16 || d == -16 { // equal characters, or the one blind spot
			continue
		}
		bad := plain[:i] + string(plain[i+1]) + string(plain[i]) + plain[i+2:]
		if _, err := ParseRecoveryCode(bad); err == nil {
			t.Fatalf("transposition at %d accepted", i)
		}
	}
	for _, bad := range []string{"", "A", plain[:32], plain + "A", strings.Repeat("1", 33), strings.Repeat("!", 33)} {
		if _, err := ParseRecoveryCode(bad); !errors.Is(err, ErrRecoveryCode) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, _, err := NewRecoveryCode(failRand{}); err == nil {
		t.Fatal("rng failure swallowed")
	}
}

func FuzzParseBody(f *testing.F) {
	f.Add(sampleBody().Marshal())
	f.Add([]byte{})
	f.Add(make([]byte, BodySize))
	f.Fuzz(func(t *testing.T, p []byte) {
		b, g, err := ParseBody(p, 1<<44)
		if err != nil {
			return
		}
		if g.End > 1<<44 || g.Sectors != b.Sectors || g.JournalEntries != b.JournalEntries {
			t.Fatalf("accepted inconsistent body: %+v %+v", b, g)
		}
		if !bytes.Equal(b.Marshal(), p) {
			t.Fatal("parse then marshal is not the identity")
		}
	})
}

func FuzzOpenLocator(f *testing.F) {
	f.Add(make([]byte, SlotSize))
	f.Add([]byte{})
	kek := kdf.KEK([]byte("fuzz"), "pw")
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, ok := OpenLocator(&kek, b); ok && (len(l.CredID) == 0 || len(l.CredID) > MaxCredID) {
			t.Fatal("locator outside its bounds")
		}
	})
}

// referenceParse is the straightforward parser (upper-case, table lookups,
// encoding/base32) that the constant-time one must agree with exactly.
func referenceParse(s string) ([]byte, bool) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\n", "", "\t", "").Replace(s))
	if len(s) != 33 {
		return nil, false
	}
	sum := 0
	for i := 0; i < 33; i++ {
		v := strings.IndexByte(alphabet, s[i])
		if v < 0 {
			return nil, false
		}
		if i < 32 {
			sum += (2*i + 1) * v
		}
	}
	if alphabet[sum%32] != s[32] {
		return nil, false
	}
	raw, err := b32.DecodeString(s[:32])
	return raw, err == nil
}

func TestRecoveryCodeMatchesReference(t *testing.T) {
	for n := 0; n < 2000; n++ {
		raw, printed, err := NewRecoveryCode(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseRecoveryCode(printed)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%q: %v", printed, err)
		}
	}
	// Every byte value in every position: accepted exactly when the
	// reference accepts, with the same bytes.
	_, printed, _ := NewRecoveryCode(rand.Reader)
	plain := strings.ReplaceAll(printed, "-", "")
	for i := 0; i < 33; i++ {
		for c := 0; c < 256; c++ {
			s := plain[:i] + string([]byte{byte(c)}) + plain[i+1:]
			got, err := ParseRecoveryCode(s)
			want, ok := referenceParse(s)
			if (err == nil) != ok || !bytes.Equal(got, want) {
				t.Fatalf("position %d byte %#x: got %x %v, reference %x %v", i, c, got, err, want, ok)
			}
		}
	}
}

func FuzzParseRecoveryCode(f *testing.F) {
	_, printed, _ := NewRecoveryCode(bytes.NewReader(make([]byte, 20)))
	f.Add(printed)
	f.Add(strings.ToLower(printed))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		raw, err := ParseRecoveryCode(s)
		want, ok := referenceParse(s)
		if (err == nil) != ok || !bytes.Equal(raw, want) {
			t.Fatalf("%q: got %x %v, reference %x %v", s, raw, err, want, ok)
		}
	})
}
