package format

import "testing"

// DerivedAuth survives Marshal and ParseBody, alone and with a TPM identity,
// and its absence stays absent.
func TestBodyDerivedAuth(t *testing.T) {
	for _, withID := range []bool{false, true} {
		for _, derived := range []bool{false, true} {
			b := sampleBody()
			b.Counter = &Counter{Handle: 0x01500000, Name: []byte{0, 0x0B, 1}, Bound: 7, DerivedAuth: derived}
			if withID {
				b.Counter.TPMID = make([]byte, IDSize)
			}
			got, _, err := ParseBody(b.Marshal(), 1<<50)
			if err != nil {
				t.Fatalf("id %v derived %v: %v", withID, derived, err)
			}
			if got.Counter.DerivedAuth != derived || (got.Counter.TPMID != nil) != withID {
				t.Fatalf("id %v derived %v: got %+v", withID, derived, got.Counter)
			}
		}
	}
}
