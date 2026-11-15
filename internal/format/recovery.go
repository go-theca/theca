package format

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"
	"strings"
)

// RecoveryBytes is the entropy of a recovery code: 160 bits (DESIGN 6.2).
const RecoveryBytes = 20

// ErrRecoveryCode is returned for a malformed or mistyped recovery code.
var ErrRecoveryCode = errors.New("format: invalid recovery code")

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// NewRecoveryCode draws 160 random bits and returns them with their printed
// form: 32 base32 characters plus a check symbol, in groups of four.
func NewRecoveryCode(rng io.Reader) (raw []byte, printed string, err error) {
	raw = make([]byte, RecoveryBytes)
	if _, err = io.ReadFull(rng, raw); err != nil {
		return nil, "", err
	}
	s := b32.EncodeToString(raw)
	s += string(alphabet[checkSymbol(s)])
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return raw, strings.Join(parts, "-"), nil
}

// checkSymbol is the sum of the 5-bit values weighted by 2i+1, modulo 32.
// Odd weights are invertible modulo 32, so every single-character
// substitution is caught; an adjacent transposition is caught unless the two
// characters differ by exactly 16. It is a typo guard only.
func checkSymbol(s string) int {
	sum := 0
	for i := 0; i < len(s); i++ {
		sum += (2*i + 1) * strings.IndexByte(alphabet, s[i])
	}
	return sum % 32
}

// ParseRecoveryCode accepts the printed form in any case, with or without
// separators, and returns the 20 raw bytes.
func ParseRecoveryCode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\n", "", "\t", "").Replace(s))
	if len(s) != 33 {
		return nil, ErrRecoveryCode
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return nil, ErrRecoveryCode
		}
	}
	want := byte(alphabet[checkSymbol(s[:32])])
	if subtle.ConstantTimeByteEq(want, s[32]) != 1 {
		return nil, ErrRecoveryCode
	}
	// 32 characters of the alphabet are exactly 160 bits: no decode error.
	raw, _ := b32.DecodeString(s[:32])
	return raw, nil
}
