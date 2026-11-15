package ta1

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"math/bits"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- independent references, written from the specifications -------------

// refHMAC is HMAC-SHA-256 from RFC 2104, built on bare SHA-256.
func refHMAC(key, msg []byte) []byte {
	if len(key) > 64 {
		s := sha256.Sum256(key)
		key = s[:]
	}
	k := make([]byte, 64)
	copy(k, key)
	in := make([]byte, 0, 64+len(msg))
	out := make([]byte, 64)
	for i := range k {
		in = append(in, k[i]^0x36)
		out[i] = k[i] ^ 0x5c
	}
	in = append(in, msg...)
	h := sha256.Sum256(in)
	o := sha256.Sum256(append(out, h[:]...))
	return o[:]
}

// refAESCTR is the SP 800-38A CTR keystream from raw AES block calls and a
// big-integer counter: no crypto/cipher CTR involved.
func refAESCTR(key, iv, data []byte) []byte {
	blk, _ := aes.NewCipher(key)
	ctr := new(big.Int).SetBytes(iv)
	mod := new(big.Int).Lsh(big.NewInt(1), 128)
	out := make([]byte, len(data))
	var ks, cb [16]byte
	for off := 0; off < len(data); off += 16 {
		ctr.FillBytes(cb[:])
		blk.Encrypt(ks[:], cb[:])
		for j := 0; j < 16 && off+j < len(data); j++ {
			out[off+j] = data[off+j] ^ ks[j]
		}
		ctr.Add(ctr, big.NewInt(1)).Mod(ctr, mod)
	}
	return out
}

func qr(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

func chachaState(key []byte, counter uint32, nonce []byte) [16]uint32 {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	s[12] = counter
	for i := 0; i < 3; i++ {
		s[13+i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	return s
}

func rounds(s *[16]uint32) {
	for i := 0; i < 10; i++ {
		qr(s, 0, 4, 8, 12)
		qr(s, 1, 5, 9, 13)
		qr(s, 2, 6, 10, 14)
		qr(s, 3, 7, 11, 15)
		qr(s, 0, 5, 10, 15)
		qr(s, 1, 6, 11, 12)
		qr(s, 2, 7, 8, 13)
		qr(s, 3, 4, 9, 14)
	}
}

// refChaCha20 is RFC 8439 section 2.3/2.4 with a 12-byte nonce.
func refChaCha20(key []byte, counter uint32, nonce, data []byte) []byte {
	out := make([]byte, len(data))
	for off := 0; off < len(data); off += 64 {
		init := chachaState(key, counter+uint32(off/64), nonce)
		w := init
		rounds(&w)
		var ks [64]byte
		for i := range w {
			binary.LittleEndian.PutUint32(ks[4*i:], w[i]+init[i])
		}
		for j := 0; j < 64 && off+j < len(data); j++ {
			out[off+j] = data[off+j] ^ ks[j]
		}
	}
	return out
}

// refHChaCha20 is draft-irtf-cfrg-xchacha section 2.2.
func refHChaCha20(key, nonce16 []byte) []byte {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	for i := 0; i < 4; i++ {
		s[12+i] = binary.LittleEndian.Uint32(nonce16[4*i:])
	}
	rounds(&s)
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], s[i])
		binary.LittleEndian.PutUint32(out[16+4*i:], s[12+i])
	}
	return out
}

// refXChaCha20 is the draft's construction: ChaCha20 under the HChaCha20
// subkey with nonce 0^4 || n[16:24].
func refXChaCha20(key, nonce24, data []byte) []byte {
	sub := refHChaCha20(key, nonce24[:16])
	n := make([]byte, 12)
	copy(n[4:], nonce24[16:])
	return refChaCha20(sub, 0, n, data)
}

// ---- known-answer tests --------------------------------------------------

func TestRFC4231(t *testing.T) {
	// RFC 4231 test cases 1, 2 and 6 (key longer than the block).
	cases := []struct{ key, data, mac string }{
		{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
		{"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{string(bytes.Repeat([]byte("aa"), 131)),
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
	}
	for i, c := range cases {
		got := refHMAC(unhex(t, c.key), unhex(t, c.data))
		if hex.EncodeToString(got) != c.mac {
			t.Errorf("RFC 4231 case %d: reference HMAC = %x", i, got)
		}
	}
}

func TestRFC8439ChaCha20(t *testing.T) {
	// RFC 8439 section 2.4.2.
	key := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := unhex(t, "000000000000004a00000000")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
	if got := refChaCha20(key, 1, nonce, pt); hex.EncodeToString(got) != want {
		t.Fatalf("reference ChaCha20 = %x", got)
	}
}

func TestHChaCha20Vector(t *testing.T) {
	// draft-irtf-cfrg-xchacha section 2.2.1.
	key := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := unhex(t, "000000090000004a0000000031415927")
	want := "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
	if got := refHChaCha20(key, nonce); hex.EncodeToString(got) != want {
		t.Fatalf("HChaCha20 = %x", got)
	}
}

func TestXChaCha20AgainstReference(t *testing.T) {
	var key [32]byte
	var nonce [24]byte
	for i := range key {
		key[i] = byte(0x80 + i)
	}
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	pt := make([]byte, 1000)
	rand.Read(pt)
	got := make([]byte, len(pt))
	xchacha20(&key, &nonce, got, pt)
	if !bytes.Equal(got, refXChaCha20(key[:], nonce[:], pt)) {
		t.Fatal("xchacha20 differs from the draft construction")
	}
}

func TestAESCTRNISTVector(t *testing.T) {
	// NIST SP 800-38A F.5.5, CTR-AES256.Encrypt, blocks 1 and 2.
	key := (*[32]byte)(unhex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
	iv := (*[16]byte)(unhex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
	pt := unhex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
	want := "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
	got := make([]byte, len(pt))
	aes256ctr(key, iv, got, pt)
	if hex.EncodeToString(got) != want {
		t.Fatalf("AES-256-CTR = %x", got)
	}
	if hex.EncodeToString(refAESCTR(key[:], iv[:], pt)) != want {
		t.Fatal("reference AES-CTR does not match the NIST vector")
	}
}

// ---- the composition -----------------------------------------------------

func testKeys(t testing.TB) *Keys {
	t.Helper()
	k, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestCascadeDecomposition: the cascade is XChaCha20 applied to the AES-CTR
// output, each computed separately and by independent code (DESIGN 3.1).
func TestCascadeDecomposition(t *testing.T) {
	k := testKeys(t)
	for _, n := range []int{0, 1, 15, 16, 63, 64, 65, 4096, 5000} {
		pt := make([]byte, n)
		rand.Read(pt)
		var seed [SeedSize]byte
		rand.Read(seed[:])
		got := make([]byte, n)
		if err := k.Cascade(got, pt, &seed); err != nil {
			t.Fatal(err)
		}
		step := refAESCTR(k.Ka[:], seed[24:], pt)
		want := refXChaCha20(k.Kc[:], seed[:24], step)
		if !bytes.Equal(got, want) {
			t.Fatalf("n=%d: cascade != XChaCha20(AES-CTR(P))", n)
		}
		// Additive stream ciphers commute (Maurer-Massey): the other order.
		other := refAESCTR(k.Ka[:], seed[24:], refXChaCha20(k.Kc[:], seed[:24], pt))
		if !bytes.Equal(got, other) {
			t.Fatalf("n=%d: layers do not commute", n)
		}
		// In place.
		cp := append([]byte(nil), pt...)
		if err := k.Cascade(cp, cp, &seed); err != nil || !bytes.Equal(cp, got) {
			t.Fatalf("n=%d: in-place cascade differs", n)
		}
	}
}

// TestAESCounterCarry: a sector's 256 AES blocks must increment the 128-bit
// counter with carry, including across the low 64 bits.
func TestAESCounterCarry(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])
	iv := (*[16]byte)(unhex(t, "00000000000000000000000000ffffff"))
	iv2 := (*[16]byte)(unhex(t, "0000000000000000ffffffffffffffff"))
	iv3 := (*[16]byte)(unhex(t, "ffffffffffffffffffffffffffffff80")) // wraps to zero after 128 blocks
	for _, v := range []*[16]byte{iv, iv2, iv3} {
		pt := make([]byte, SectorSize)
		got := make([]byte, SectorSize)
		aes256ctr(&key, v, got, pt)
		if !bytes.Equal(got, refAESCTR(key[:], v[:], pt)) {
			t.Fatalf("carry mismatch at iv %x", v)
		}
	}
}

func TestMACAgainstReference(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	rand.Read(cid[:])
	var seed [SeedSize]byte
	rand.Read(seed[:])
	ct := make([]byte, SectorSize)
	rand.Read(ct)

	lab := func(l string) []byte { return append([]byte{byte(len(l))}, l...) }
	u64 := func(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }
	cat := func(p ...[]byte) []byte { return bytes.Join(p, nil) }

	tag := k.SectorTag(&cid, 77, &seed, ct)
	want := refHMAC(k.Km[:], cat(lab(LabelLeaf), cid[:], u64(77), seed[:], ct))
	if !bytes.Equal(tag[:], want[:SectorTagSize]) {
		t.Fatal("sector tag differs from the reference HMAC")
	}
	m := k.MAC(LabelNode, []byte{3}, ct)
	if !bytes.Equal(m[:], refHMAC(k.Km[:], cat(lab(LabelNode), []byte{3}, ct))) {
		t.Fatal("MAC differs from the reference HMAC")
	}
	ad := []byte("assoc")
	blob, err := k.Seal(LabelHeader, ad, ct[:100], rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantTag := refHMAC(k.Km[:], cat(lab(LabelHeader), u64(uint64(len(ad))), ad, blob[:len(blob)-SealTagSize]))
	if !bytes.Equal(blob[len(blob)-SealTagSize:], wantTag) {
		t.Fatal("seal tag differs from the reference HMAC")
	}
}

func TestSectorRoundTripAndFreshSeed(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	rand.Read(cid[:])
	pt := make([]byte, SectorSize)
	rand.Read(pt)
	ct := make([]byte, SectorSize)
	s1, t1, err := k.SealSector(&cid, 9, ct, pt, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, SectorSize)
	if err := k.OpenSector(&cid, 9, out, ct, &s1, &t1); err != nil || !bytes.Equal(out, pt) {
		t.Fatalf("round trip failed: %v", err)
	}
	// Rewriting identical data draws a new seed and gives different bytes
	// (DESIGN 10.3).
	ct2 := make([]byte, SectorSize)
	s2, t2, _ := k.SealSector(&cid, 9, ct2, pt, rand.Reader)
	if s1 == s2 || bytes.Equal(ct, ct2) || t1 == t2 {
		t.Fatal("identical rewrite reused its seed")
	}
}

// TestSectorTamper flips every byte class of a sector: ciphertext, seed, tag,
// sector index and container id.
func TestSectorTamper(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	rand.Read(cid[:])
	pt := make([]byte, SectorSize)
	ct := make([]byte, SectorSize)
	seed, tag, _ := k.SealSector(&cid, 5, ct, pt, rand.Reader)
	out := make([]byte, SectorSize)

	flip := func(name string, f func(c []byte, s *[SeedSize]byte, g *[SectorTagSize]byte, id *[16]byte, i *uint64)) {
		c := append([]byte(nil), ct...)
		s, g, id, i := seed, tag, cid, uint64(5)
		f(c, &s, &g, &id, &i)
		if err := k.OpenSector(&id, i, out, c, &s, &g); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: err = %v, want ErrAuth", name, err)
		}
	}
	for _, pos := range []int{0, 1, 2047, 4095} {
		flip("ciphertext", func(c []byte, _ *[SeedSize]byte, _ *[SectorTagSize]byte, _ *[16]byte, _ *uint64) { c[pos] ^= 1 })
	}
	for pos := 0; pos < SeedSize; pos++ {
		flip("seed", func(_ []byte, s *[SeedSize]byte, _ *[SectorTagSize]byte, _ *[16]byte, _ *uint64) { s[pos] ^= 0x80 })
	}
	for pos := 0; pos < SectorTagSize; pos++ {
		flip("tag", func(_ []byte, _ *[SeedSize]byte, g *[SectorTagSize]byte, _ *[16]byte, _ *uint64) { g[pos] ^= 1 })
	}
	flip("index (sector swap)", func(_ []byte, _ *[SeedSize]byte, _ *[SectorTagSize]byte, _ *[16]byte, i *uint64) { *i = 6 })
	flip("cid (splice from another container)", func(_ []byte, _ *[SeedSize]byte, _ *[SectorTagSize]byte, id *[16]byte, _ *uint64) { id[0] ^= 1 })

	other := testKeys(t)
	if err := other.OpenSector(&cid, 5, out, ct, &seed, &tag); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	k := testKeys(t)
	for _, n := range []int{0, 1, 96, 8120} {
		pt := make([]byte, n)
		rand.Read(pt)
		blob, err := k.Seal(LabelSlot, []byte("ad"), pt, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(blob) != n+SealOverhead {
			t.Fatalf("overhead: %d", len(blob)-n)
		}
		got, err := k.Open(LabelSlot, []byte("ad"), blob)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("n=%d: %v", n, err)
		}
		// Every byte of the object is covered by the tag.
		for i := 0; i < len(blob); i++ {
			b := append([]byte(nil), blob...)
			b[i] ^= 1
			if _, err := k.Open(LabelSlot, []byte("ad"), b); !errors.Is(err, ErrAuth) {
				t.Fatalf("n=%d byte %d: %v", n, i, err)
			}
		}
		if _, err := k.Open(LabelHeader, []byte("ad"), blob); !errors.Is(err, ErrAuth) {
			t.Fatal("label not bound")
		}
		if _, err := k.Open(LabelSlot, []byte("AD"), blob); !errors.Is(err, ErrAuth) {
			t.Fatal("associated data not bound")
		}
	}
}

func TestKeyCommitment(t *testing.T) {
	// Two different keys never open one object (32-byte keys, DESIGN 9.3).
	a, b := testKeys(t), testKeys(t)
	blob, _ := a.Seal(LabelHeader, nil, []byte("x"), rand.Reader)
	if _, err := b.Open(LabelHeader, nil, blob); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
	// Commitment is carried by the 32-byte MAC key Km alone: a different Km
	// fails, while a different cipher key with the same Km passes the tag and
	// returns other plaintext. Theca therefore never accepts cipher keys that
	// were not derived together with Km (a slot yields all three at once).
	c := *a
	c.Km[0] ^= 1
	if _, err := c.Open(LabelHeader, nil, blob); !errors.Is(err, ErrAuth) {
		t.Fatal("a different Km opened the object")
	}
	d := *a
	d.Ka[0] ^= 1
	got, err := d.Open(LabelHeader, nil, blob)
	if err != nil || bytes.Equal(got, []byte("x")) {
		t.Fatalf("different Ka: err=%v, plaintext unchanged", err)
	}
}

func TestUntagged(t *testing.T) {
	k := testKeys(t)
	pt := []byte("locator bytes")
	blob, err := k.SealUntagged(pt, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.OpenUntagged(blob)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	// A wrong key answers garbage, never an error: no verifier.
	g2, err := testKeys(t).OpenUntagged(blob)
	if err != nil || bytes.Equal(g2, pt) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := k.OpenUntagged(blob[:SeedSize-1]); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestErrors(t *testing.T) {
	k := testKeys(t)
	var cid [16]byte
	buf := make([]byte, SectorSize)
	if _, _, err := k.SealSector(&cid, 0, buf, buf, failReader{}); !errors.Is(err, ErrNoRand) {
		t.Fatal(err)
	}
	if _, _, err := k.SealSector(&cid, 0, buf[:10], buf, rand.Reader); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := k.Seal("l", nil, nil, failReader{}); !errors.Is(err, ErrNoRand) {
		t.Fatal(err)
	}
	if _, err := k.SealUntagged(nil, failReader{}); !errors.Is(err, ErrNoRand) {
		t.Fatal(err)
	}
	if _, err := Generate(failReader{}); !errors.Is(err, ErrNoRand) {
		t.Fatal(err)
	}
	big := make([]byte, MaxObject+1)
	if _, err := k.Seal("l", nil, big, rand.Reader); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := k.SealUntagged(big, rand.Reader); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := k.Open("l", nil, make([]byte, SealOverhead-1)); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := k.Open("l", nil, make([]byte, MaxObject+SealOverhead+1)); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, err := k.OpenUntagged(make([]byte, MaxObject+SeedSize+1)); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	if _, _, err := k.SealSector(&cid, 0, buf, buf[:100], rand.Reader); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
	for _, l := range []string{LabelLeaf, LabelSlot, LabelHeader, string(make([]byte, 300))} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("MAC accepted label %q", l)
				}
			}()
			k.MAC(l)
		}()
	}
	if err := k.Cascade(buf, big, (*[SeedSize]byte)(make([]byte, SeedSize))); !errors.Is(err, ErrSize) {
		t.Fatal(err)
	}
}

func TestKeysBytes(t *testing.T) {
	k := testKeys(t)
	k2, err := FromBytes(k.Bytes())
	if err != nil || *k2 != *k {
		t.Fatal(err)
	}
	if _, err := FromBytes(make([]byte, 95)); err == nil {
		t.Fatal("short master secret accepted")
	}
	k.Zeroize()
	if *k != (Keys{}) {
		t.Fatal("not zeroised")
	}
}

func FuzzOpen(f *testing.F) {
	k := &Keys{}
	// Deterministic, so a committed corpus entry stays meaningful.
	blob, _ := k.Seal(LabelSlot, nil, []byte("seed corpus"), bytes.NewReader(make([]byte, SeedSize)))
	f.Add(blob)
	f.Add([]byte{})
	f.Add(make([]byte, SealOverhead))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := k.Open(LabelSlot, nil, b); err == nil && !bytes.Equal(b, blob) {
			// Only the genuine object may open (anything else would be a
			// forgery).
			t.Fatalf("forged object accepted: %x", b)
		}
		k.OpenUntagged(b)
	})
}
