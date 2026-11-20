package kdf

import (
	"bytes"
	"testing"

	"github.com/go-theca/theca/internal/ta1"
)

// The derived counter authValue is a function of the master secret alone, is
// 32 bytes, never ends in a zero octet (a TPM strips those), and another master
// secret gives another value.
func TestCounterAuth(t *testing.T) {
	a, _ := ta1.FromBytes(bytes.Repeat([]byte{1}, ta1.MSSize))
	b, _ := ta1.FromBytes(bytes.Repeat([]byte{2}, ta1.MSSize))
	x, y := CounterAuth(a), CounterAuth(a)
	if len(x) != CounterAuthSize || !bytes.Equal(x, y) {
		t.Fatalf("%x %x", x, y)
	}
	if bytes.Equal(x, CounterAuth(b)) {
		t.Fatal("two master secrets, one counter authValue")
	}
	// The master key is not left altered or wiped by the derivation.
	if !bytes.Equal(a.Bytes(), bytes.Repeat([]byte{1}, ta1.MSSize)) {
		t.Fatal("the derivation changed the master secret")
	}
	// Whatever the HKDF output, the last octet is non-zero: 512 master secrets
	// are far more than the 1-in-256 that would end in zero without the guard.
	for i := 0; i < 512; i++ {
		m := bytes.Repeat([]byte{byte(i)}, ta1.MSSize)
		m[0] = byte(i >> 8)
		k, _ := ta1.FromBytes(m)
		if v := CounterAuth(k); v[len(v)-1] == 0 {
			t.Fatalf("master %d: authValue ends in zero", i)
		}
	}
}
