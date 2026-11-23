package ta1

import (
	"fmt"
	"testing"
)

// BenchmarkMAC measures one keyed HMAC-SHA-256 (Reset, Write, Sum) at a tag
// header, a sector and a Merkle-sized buffer.
func BenchmarkMAC(b *testing.B) {
	k := testKeys(b)
	for _, n := range []int{64, 4096, 1 << 20} {
		data := make([]byte, n)
		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = k.MAC(LabelNode, data)
			}
		})
	}
}
