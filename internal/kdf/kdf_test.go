package kdf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// ---- a naive Argon2id, written from RFC 9106 sections 3.2-3.4 ------------
//
// It is the independent oracle for the profile wiring: x/crypto's IDKey has
// no secret or associated-data input, so the RFC's own test vector (section
// 5.3) can only be checked against a reference that has them.

type block [128]uint64

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func blake(size int, parts ...[]byte) []byte {
	h, _ := blake2b.New(size, nil)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// hprime is H' of RFC 9106 section 3.3.
func hprime(t int, x []byte) []byte {
	if t <= 64 {
		return blake(t, le32(uint32(t)), x)
	}
	r := (t+31)/32 - 2
	v := blake(64, le32(uint32(t)), x)
	out := append([]byte(nil), v[:32]...)
	for i := 2; i <= r; i++ {
		v = blake(64, v)
		out = append(out, v[:32]...)
	}
	v = blake(t-32*r, v)
	return append(out, v...)
}

func gb(a, b, c, d *uint64) {
	lo := func(x uint64) uint64 { return x & 0xffffffff }
	*a = *a + *b + 2*lo(*a)*lo(*b)
	*d = bits.RotateLeft64(*d^*a, -32)
	*c = *c + *d + 2*lo(*c)*lo(*d)
	*b = bits.RotateLeft64(*b^*c, -24)
	*a = *a + *b + 2*lo(*a)*lo(*b)
	*d = bits.RotateLeft64(*d^*a, -16)
	*c = *c + *d + 2*lo(*c)*lo(*d)
	*b = bits.RotateLeft64(*b^*c, -63)
}

func perm(v []*uint64) {
	gb(v[0], v[4], v[8], v[12])
	gb(v[1], v[5], v[9], v[13])
	gb(v[2], v[6], v[10], v[14])
	gb(v[3], v[7], v[11], v[15])
	gb(v[0], v[5], v[10], v[15])
	gb(v[1], v[6], v[11], v[12])
	gb(v[2], v[7], v[8], v[13])
	gb(v[3], v[4], v[9], v[14])
}

func compress(x, y *block) block {
	var r, z block
	for i := range r {
		r[i] = x[i] ^ y[i]
	}
	z = r
	for i := 0; i < 8; i++ {
		v := make([]*uint64, 16)
		for j := range v {
			v[j] = &z[16*i+j]
		}
		perm(v)
	}
	for i := 0; i < 8; i++ {
		v := make([]*uint64, 16)
		for j := 0; j < 8; j++ {
			v[2*j] = &z[2*i+16*j]
			v[2*j+1] = &z[2*i+16*j+1]
		}
		perm(v)
	}
	for i := range z {
		z[i] ^= r[i]
	}
	return z
}

func toBlock(b []byte) (o block) {
	for i := range o {
		o[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	return
}

func refArgon2id(pw, salt, secret, ad []byte, t, m, p, tagLen uint32) []byte {
	lp := func(b []byte) []byte { return append(le32(uint32(len(b))), b...) }
	h0 := blake(64, le32(p), le32(tagLen), le32(m), le32(t), le32(0x13), le32(2),
		lp(pw), lp(salt), lp(secret), lp(ad))
	mp := 4 * p * (m / (4 * p))
	q := mp / p
	seg := q / 4
	B := make([][]block, p)
	for l := range B {
		B[l] = make([]block, q)
		B[l][0] = toBlock(hprime(1024, append(append(append([]byte(nil), h0...), le32(0)...), le32(uint32(l))...)))
		B[l][1] = toBlock(hprime(1024, append(append(append([]byte(nil), h0...), le32(1)...), le32(uint32(l))...)))
	}
	for r := uint32(0); r < t; r++ {
		for s := uint32(0); s < 4; s++ {
			for l := uint32(0); l < p; l++ {
				indep := r == 0 && s < 2
				var zin, addr block
				next := func() {
					zin[6]++
					var zero block
					addr = compress(&zero, ptr(compress(&zero, &zin)))
				}
				if indep {
					zin[0], zin[1], zin[2], zin[3], zin[4], zin[5] = uint64(r), uint64(l), uint64(s), uint64(mp), uint64(t), 2
				}
				first := uint32(0)
				if r == 0 && s == 0 {
					first = 2
					if indep {
						next()
					}
				}
				for idx := first; idx < seg; idx++ {
					j := s*seg + idx
					prevCol := j - 1
					if j == 0 {
						prevCol = q - 1
					}
					prev := B[l][prevCol]
					var rnd uint64
					if indep {
						if idx%128 == 0 {
							next()
						}
						rnd = addr[idx%128]
					} else {
						rnd = prev[0]
					}
					j1, j2 := uint32(rnd), uint32(rnd>>32)
					refLane := j2 % p
					if r == 0 && s == 0 {
						refLane = l
					}
					same := refLane == l
					var area uint32
					switch {
					case r == 0 && s == 0:
						area = idx - 1
					case r == 0 && same:
						area = s*seg + idx - 1
					case r == 0:
						area = s * seg
						if idx == 0 {
							area--
						}
					case same:
						area = q - seg + idx - 1
					default:
						area = q - seg
						if idx == 0 {
							area--
						}
					}
					x := uint64(j1) * uint64(j1) >> 32
					y := uint64(area) * x >> 32
					zz := uint64(area) - 1 - y
					startPos := uint64(0)
					if r != 0 && s != 3 {
						startPos = uint64((s + 1) * seg)
					}
					ref := B[refLane][(startPos+zz)%uint64(q)]
					nb := compress(&prev, &ref)
					if r > 0 {
						for i := range nb {
							nb[i] ^= B[l][j][i]
						}
					}
					B[l][j] = nb
				}
			}
		}
	}
	var c block
	for l := range B {
		for i := range c {
			c[i] ^= B[l][q-1][i]
		}
	}
	raw := make([]byte, 1024)
	for i := range c {
		binary.LittleEndian.PutUint64(raw[8*i:], c[i])
	}
	return hprime(int(tagLen), raw)
}

func ptr(b block) *block { return &b }

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// TestRFC9106Vector checks the reference against RFC 9106 section 5.3
// (Argon2id, with secret and associated data). The reference then stands as
// the oracle for the profile wiring below.
func TestRFC9106Vector(t *testing.T) {
	got := refArgon2id(rep(1, 32), rep(2, 16), rep(3, 8), rep(4, 12), 3, 32, 4, 32)
	want := "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
	if hex.EncodeToString(got) != want {
		t.Fatalf("reference Argon2id = %x, want %s", got, want)
	}
}

func TestArgon2idMatchesReference(t *testing.T) {
	saved := Table
	defer func() { Table = saved }()
	salt := rep(7, SaltSize)
	for i, p := range []Profile{
		{Time: 1, MemKiB: 64, Threads: 4},
		{Time: 3, MemKiB: 256, Threads: 4},
		{Time: 2, MemKiB: 4096, Threads: 2}, // > 128 blocks per segment: address-block refills
	} {
		Table[i] = p
		got, err := Argon2id(i, []byte("correct horse"), salt)
		if err != nil {
			t.Fatal(err)
		}
		want := refArgon2id([]byte("correct horse"), salt, nil, nil, p.Time, p.MemKiB, uint32(p.Threads), KeySize)
		if !bytes.Equal(got, want) {
			t.Fatalf("profile %d: IDKey %x != reference %x", i, got, want)
		}
	}
}

func TestTableIsTheRFCTable(t *testing.T) {
	// RFC 9106 section 4: FIRST t=1 p=4 m=2 GiB; SECOND t=3 p=4 m=64 MiB.
	if Table[0] != (Profile{1, 2 << 20, 4}) || Table[1] != (Profile{3, 64 << 10, 4}) ||
		Table[2] != (Profile{3, 4 << 20, 4}) {
		t.Fatalf("table changed: %+v", Table)
	}
}

func TestErrors(t *testing.T) {
	for _, h := range []int{-1, 3, 255} {
		if _, err := Argon2id(h, nil, rep(0, SaltSize)); !errors.Is(err, ErrProfile) {
			t.Errorf("hint %d: %v", h, err)
		}
	}
	if _, err := Argon2id(1, nil, rep(0, 5)); err == nil {
		t.Error("short salt accepted")
	}
	// A 32-bit platform cannot hold profile 0 (2 GiB): refuse, don't crash.
	saved := platformMax
	platformMax = 1<<31 - 1
	defer func() { platformMax = saved }()
	if _, err := Argon2id(0, nil, rep(0, SaltSize)); !errors.Is(err, ErrProfile) {
		t.Errorf("oversize profile: %v", err)
	}
}

func TestKeysExpandsOneKEKIntoThreeDistinctKeys(t *testing.T) {
	kek := KEK(rep(5, 32), "pw")
	k := Keys(&kek)
	if k.Kc == k.Ka || k.Ka == k.Km || k.Kc == k.Km {
		t.Fatal("expanded keys repeat")
	}
	prk := hmacSHA256(make([]byte, 32), kek[:])
	info := []byte("theca/v1/TA1/slot/keys")
	var okm, prev []byte
	for i := byte(1); len(okm) < 96; i++ {
		prev = hmacSHA256(prk, append(append(append([]byte(nil), prev...), info...), i))
		okm = append(okm, prev...)
	}
	if !bytes.Equal(k.Bytes(), okm[:96]) {
		t.Fatal("Keys differs from RFC 5869")
	}
	kek2 := KEK(rep(6, 32), "pw")
	if *Keys(&kek2) == *k {
		t.Fatal("different KEKs gave equal keys")
	}
}

// The expected values below are RFC 5869 computed from bare HMAC-SHA-256.
func TestFIDO2SaltMatchesRFC5869(t *testing.T) {
	// HKDF(salt = nil, IKM = partner KEK, info = "theca/v1/fido2/salt/<kind>").
	kek := KEK(rep(3, 32), "pw")
	prk := hmacSHA256(make([]byte, 32), kek[:])
	want := hmacSHA256(prk, append([]byte("theca/v1/fido2/salt/pw"), 1))
	got := FIDO2Salt(&kek, "pw")
	if !bytes.Equal(got[:], want) {
		t.Fatal("FIDO2Salt differs from RFC 5869")
	}
	// A different partner (a wrong password) or kind gives another salt, and
	// the salt is never the KEK itself.
	other := KEK(rep(4, 32), "pw")
	if FIDO2Salt(&other, "pw") == got || FIDO2Salt(&kek, "rc") == got || got == kek {
		t.Fatal("salt not separated by partner, kind, or from the KEK")
	}
}

func TestHKDFMatchesRFC5869(t *testing.T) {
	// The KEK is HKDF(salt = nil, info = prefix+kind), one 32-byte block:
	// T(1) = HMAC(PRK, info || 0x01) with PRK = HMAC(0^32, IKM).
	secret := rep(9, 32)
	prk := hmacSHA256(make([]byte, 32), secret)
	want := hmacSHA256(prk, append([]byte("theca/v1/TA1/slot/pw"), 1))
	got := KEK(secret, "pw")
	if !bytes.Equal(got[:], want) {
		t.Fatal("KEK differs from RFC 5869")
	}
	a, b := KEK(rep(1, 32), "pw"), KEK(rep(2, 32), "rc")
	pair := Pair(&a, "pw", &b, "rc")
	prk = hmacSHA256(make([]byte, 32), append(append([]byte(nil), a[:]...), b[:]...))
	want = hmacSHA256(prk, append([]byte("theca/v1/TA1/slot/pair/pw+rc"), 1))
	if !bytes.Equal(pair[:], want) {
		t.Fatal("pair KEK differs from RFC 5869")
	}
	// Domain separation between kinds; argument order does not matter.
	if KEK(secret, "pw") == KEK(secret, "rc") {
		t.Fatal("kinds not separated")
	}
	if Pair(&a, "pw", &b, "rc") != Pair(&b, "rc", &a, "pw") {
		t.Fatal("Pair depends on argument order")
	}
	if Pair(&a, "pw", &b, "rc") == Pair(&a, "pw", &b, "fido2") {
		t.Fatal("pairs not separated")
	}
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
