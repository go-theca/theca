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
// characters differ by exactly 16. It is a typo guard only. Used on the
// encoder side, where the input is known to be in the alphabet.
func checkSymbol(s string) int {
	sum := 0
	for i := 0; i < len(s); i++ {
		v, _ := value(s[i])
		sum += (2*i + 1) * v
	}
	return sum % 32
}

// value maps one character of the alphabet, in either case, to its 5-bit
// value without a branch or a table indexed by the secret: ok is 1 for a
// character of the alphabet and 0 otherwise, and v is 0 then.
func value(ch byte) (v, ok int) {
	c := int(ch)
	upper := subtle.ConstantTimeLessOrEq('A', c) & subtle.ConstantTimeLessOrEq(c, 'Z')
	lower := subtle.ConstantTimeLessOrEq('a', c) & subtle.ConstantTimeLessOrEq(c, 'z')
	digit := subtle.ConstantTimeLessOrEq('2', c) & subtle.ConstantTimeLessOrEq(c, '7')
	v = subtle.ConstantTimeSelect(upper, c-'A', 0) |
		subtle.ConstantTimeSelect(lower, c-'a', 0) |
		subtle.ConstantTimeSelect(digit, c-'2'+26, 0)
	return v, upper | lower | digit
}

// ParseRecoveryCode accepts the printed form in any case, with or without
// separators, and returns the 20 raw bytes.
//
// The code is a secret, so after the separators are removed (their places
// are public) its characters are classified, checksummed and decoded in
// constant time: no early exit on the first bad character, no table lookup
// indexed by a character, one comparison of the check symbol (review of PR
// #4, finding 7). Only the length, which is public, ends the work early.
func ParseRecoveryCode(s string) ([]byte, error) {
	s = strings.NewReplacer("-", "", " ", "", "\n", "", "\t", "").Replace(s)
	if len(s) != 33 {
		return nil, ErrRecoveryCode
	}
	good, sum := 1, 0
	var vals [32]int
	for i := 0; i < 32; i++ {
		v, ok := value(s[i])
		good &= ok
		vals[i] = v
		sum += (2*i + 1) * v
	}
	check, ok := value(s[32])
	good &= ok & subtle.ConstantTimeEq(int32(sum%32), int32(check))
	raw := make([]byte, RecoveryBytes)
	for g := 0; g < 4; g++ { // 4 groups of 8 characters = 40 bits = 5 bytes
		var acc uint64
		for _, v := range vals[8*g : 8*g+8] {
			acc = acc<<5 | uint64(v)
		}
		for j := 0; j < 5; j++ {
			raw[5*g+j] = byte(acc >> (32 - 8*j))
		}
	}
	clear(vals[:])
	if good != 1 {
		clear(raw)
		return nil, ErrRecoveryCode
	}
	return raw, nil
}
