package journal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/go-theca/theca/internal/ta1"
)

type mem struct{ b []byte }

func (m *mem) WriteAt(p []byte, off int64) (int, error) {
	if int(off)+len(p) > len(m.b) {
		return 0, io.ErrShortWrite
	}
	copy(m.b[off:], p)
	return len(p), nil
}

func (m *mem) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(m.b) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func keys(t testing.TB) *ta1.Keys {
	k, err := ta1.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func noSync() error { return nil }

func sample(epoch uint64, n int) *Tx {
	tx := &Tx{Epoch: epoch}
	rand.Read(tx.Root[:])
	for i := 0; i < n; i++ {
		d := make([]byte, BlockSize)
		rand.Read(d)
		tx.Records = append(tx.Records, Record{Area: Area(1 + i%3), Index: uint64(i * 7), Data: d})
	}
	return tx
}

func equal(a, b *Tx) bool {
	if a.Epoch != b.Epoch || a.Root != b.Root || len(a.Records) != len(b.Records) {
		return false
	}
	for i := range a.Records {
		x, y := a.Records[i], b.Records[i]
		if x.Area != y.Area || x.Index != y.Index || !bytes.Equal(x.Data, y.Data) {
			return false
		}
	}
	return true
}

const slots = 12

func write(t *testing.T, k *ta1.Keys, tx *Tx) *mem {
	m := &mem{b: make([]byte, slots*EntrySize)}
	if err := Write(k, m, slots, tx, rand.Reader, noSync); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRoundTrip(t *testing.T) {
	k := keys(t)
	for _, n := range []int{0, 1, 5, slots - 1} {
		tx := sample(8, n)
		m := write(t, k, tx)
		got, err := Recover(k, m, slots, 7)
		if err != nil || got == nil || !equal(got, tx) {
			t.Fatalf("n=%d: %v %v", n, got, err)
		}
	}
}

// TestReplayRefused: a genuine, fully committed transaction is accepted for
// exactly one header epoch (DESIGN 5.3, finding R1).
func TestReplayRefused(t *testing.T) {
	k := keys(t)
	m := write(t, k, sample(8, 4))
	for _, e := range []uint64{0, 6, 8, 9, 100, ^uint64(0), ^uint64(0) - 1} {
		if got, err := Recover(k, m, slots, e); err != nil || got != nil {
			t.Errorf("header epoch %d accepted a transaction for epoch 8: %v %v", e, got, err)
		}
	}
	if got, _ := Recover(k, m, slots, 7); got == nil {
		t.Fatal("the intended epoch was refused")
	}
}

func TestWrongKey(t *testing.T) {
	m := write(t, keys(t), sample(8, 3))
	if got, err := Recover(keys(t), m, slots, 7); err != nil || got != nil {
		t.Fatal("wrong key recovered something")
	}
}

// TestTamperEveryEntryByteClass flips each authenticated byte of the records
// and the commit entry; recovery must refuse the whole transaction. Pad bytes
// after the sealed object are not authenticated and are ignored by design.
func TestTamperEveryEntryByteClass(t *testing.T) {
	k := keys(t)
	tx := sample(8, 3)
	m := write(t, k, tx)
	orig := append([]byte(nil), m.b...)
	for e := 0; e <= len(tx.Records); e++ {
		sealed := recSealed
		if e == len(tx.Records) {
			sealed = comSealed
		}
		for _, pos := range []int{0, 23, 24, 39, 40, 41, 100, sealed - 33, sealed - 32, sealed - 1} {
			copy(m.b, orig)
			m.b[e*EntrySize+pos] ^= 1
			if got, _ := Recover(k, m, slots, 7); got != nil {
				t.Fatalf("entry %d byte %d: tampered transaction accepted", e, pos)
			}
		}
		copy(m.b, orig)
		m.b[e*EntrySize+sealed] ^= 1 // padding
		if got, _ := Recover(k, m, slots, 7); got == nil {
			t.Fatalf("entry %d: padding flip broke recovery", e)
		}
	}
}

func TestReorderDropSplice(t *testing.T) {
	k := keys(t)
	tx := sample(8, 4)
	m := write(t, k, tx)
	orig := append([]byte(nil), m.b...)
	swap := func(a, b int) {
		copy(m.b, orig)
		ea := append([]byte(nil), m.b[a*EntrySize:(a+1)*EntrySize]...)
		copy(m.b[a*EntrySize:], m.b[b*EntrySize:(b+1)*EntrySize])
		copy(m.b[b*EntrySize:], ea)
	}
	swap(0, 1)
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("reordered records accepted")
	}
	// Drop record 1: records shift down, positions no longer match.
	copy(m.b, orig)
	copy(m.b[1*EntrySize:], orig[2*EntrySize:5*EntrySize+EntrySize])
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("dropped record accepted")
	}
	// Splice a record of another transaction of the same epoch and keys.
	other := sample(8, 4)
	m2 := write(t, k, other)
	copy(m.b, orig)
	copy(m.b[2*EntrySize:(3)*EntrySize], m2.b[2*EntrySize:3*EntrySize])
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("spliced record accepted")
	}
	// The commit of another transaction (other records hash, other root).
	copy(m.b, orig)
	copy(m.b[4*EntrySize:5*EntrySize], m2.b[4*EntrySize:5*EntrySize])
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("foreign commit accepted")
	}
}

// TestTornWrite: a crash after the records but before the commit entry
// leaves nothing recoverable; so does a stale commit from an older, longer
// transaction of an older epoch left behind the new records.
func TestTornWrite(t *testing.T) {
	k := keys(t)
	var synced int
	m := &mem{b: make([]byte, slots*EntrySize)}
	crash := errors.New("crash")
	err := Write(k, m, slots, sample(8, 3), rand.Reader, func() error {
		synced++
		return crash // dies at the first sync, before the commit entry
	})
	if !errors.Is(err, crash) || synced != 1 {
		t.Fatalf("err=%v synced=%d", err, synced)
	}
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("transaction without a commit entry was accepted")
	}
	// An old, longer transaction (epoch 7) then a shorter new one (epoch 8):
	// the old tail must not complete the new one.
	m = write(t, k, sample(7, 6))
	if err := Write(k, m, slots, sample(8, 2), rand.Reader, func() error { return crash }); err == nil {
		t.Fatal("sync error swallowed")
	}
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("stale tail completed a torn transaction")
	}
	if got, _ := Recover(k, m, slots, 6); got != nil {
		t.Fatal("old epoch-7 transaction was damaged by the new records yet recovered")
	}
}

func TestEmptyAndShortJournal(t *testing.T) {
	k := keys(t)
	if got, err := Recover(k, &mem{b: make([]byte, slots*EntrySize)}, slots, 0); got != nil || err != nil {
		t.Fatal("zeros recovered")
	}
	if got, err := Recover(k, &mem{b: make([]byte, 10)}, slots, 0); got != nil || err != nil {
		t.Fatalf("short area: %v %v", got, err)
	}
	if got, err := Recover(k, &mem{b: make([]byte, EntrySize+5)}, slots, 0); got != nil || err != nil {
		t.Fatalf("truncated entry: %v %v", got, err)
	}
	// Full journal with no commit entry at all.
	tx := sample(1, slots)
	m := &mem{b: make([]byte, slots*EntrySize)}
	// write records only by using a journal one slot larger, then cut
	big := &mem{b: make([]byte, (slots+1)*EntrySize)}
	if err := Write(k, big, slots+1, tx, rand.Reader, noSync); err != nil {
		t.Fatal(err)
	}
	copy(m.b, big.b)
	if got, _ := Recover(k, m, slots, 0); got != nil {
		t.Fatal("journal without room for its commit entry recovered")
	}
}

type errReader struct{ err error }

func (e errReader) ReadAt([]byte, int64) (int, error) { return 0, e.err }

func TestReadError(t *testing.T) {
	bad := errors.New("io")
	if _, err := Recover(keys(t), errReader{bad}, slots, 0); !errors.Is(err, bad) {
		t.Fatal(err)
	}
}

type failWriter struct{ after int }

func (f *failWriter) WriteAt(p []byte, _ int64) (int, error) {
	if f.after == 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestWriteErrors(t *testing.T) {
	k := keys(t)
	if err := Write(k, &mem{}, 3, sample(1, 3), rand.Reader, noSync); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	bad := sample(1, 1)
	bad.Records[0].Data = bad.Records[0].Data[:10]
	if err := Write(k, &mem{}, 3, bad, rand.Reader, noSync); !errors.Is(err, ErrBlock) {
		t.Fatal(err)
	}
	for after := 0; after < 3; after++ {
		if err := Write(k, &failWriter{after}, 8, sample(1, 2), rand.Reader, noSync); err == nil {
			t.Fatalf("write error %d swallowed", after)
		}
	}
	// commit-time sync failure
	n := 0
	if err := Write(k, &mem{b: make([]byte, 4*EntrySize)}, 4, sample(1, 1), rand.Reader, func() error {
		n++
		if n == 2 {
			return errors.New("sync")
		}
		return nil
	}); err == nil {
		t.Fatal("final sync error swallowed")
	}
	// random source failures at each draw: seed of record, pad, seed of commit, pad
	for ok := 0; ok < 4; ok++ {
		r := &limitedRand{n: ok}
		if err := Write(k, &mem{b: make([]byte, 4*EntrySize)}, 4, sample(1, 1), r, noSync); err == nil {
			t.Fatalf("rng failure after %d draws swallowed", ok)
		}
	}
}

// limitedRand serves n successful Reads, then fails.
type limitedRand struct{ n int }

func (l *limitedRand) Read(p []byte) (int, error) {
	if l.n == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	l.n--
	return rand.Read(p)
}

func TestInvalidRecordParse(t *testing.T) {
	k := keys(t)
	// A correctly sealed record with a bogus area, and one of the wrong size.
	for _, plain := range [][]byte{
		append([]byte{9}, make([]byte, recPlain-1)...),
		make([]byte, recPlain-1),
	} {
		m := &mem{b: make([]byte, slots*EntrySize)}
		sealed, _ := k.Seal(ta1.LabelJournal, ad(1, 0, kindRecord), plain, rand.Reader)
		copy(m.b, sealed)
		if got, err := Recover(k, m, slots, 0); got != nil || err != nil {
			t.Fatalf("bogus record accepted: %v %v", got, err)
		}
	}
	// Commit entry that lies about the count.
	tx := sample(1, 2)
	m := write(t, k, tx)
	c, _ := k.Seal(ta1.LabelCommit, ad(1, 2, kindCommit), make([]byte, comPlain), rand.Reader)
	copy(m.b[2*EntrySize:], c)
	if got, _ := Recover(k, m, slots, 0); got != nil {
		t.Fatal("commit with a wrong count accepted")
	}
}

func FuzzRecover(f *testing.F) {
	k := &ta1.Keys{}
	m := &mem{b: make([]byte, 4*EntrySize)}
	tx := &Tx{Epoch: 1, Records: []Record{{Area: AreaData, Index: 3, Data: make([]byte, BlockSize)}}}
	Write(k, m, 4, tx, bytes.NewReader(make([]byte, 1<<16)), noSync)
	f.Add(m.b)
	f.Add([]byte{})
	f.Add(make([]byte, 3*EntrySize))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Recover(k, &mem{b: b}, 4, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			for _, r := range got.Records {
				if len(r.Data) != BlockSize {
					t.Fatal("record with a wrong block size")
				}
			}
		}
	})
}

func TestWriteRefusesAnAreaRecoveryWouldDrop(t *testing.T) {
	k := keys(t)
	for _, a := range []Area{0, 4, 9} {
		tx := sample(1, 1)
		tx.Records[0].Area = a
		if err := Write(k, &mem{}, 3, tx, rand.Reader, noSync); !errors.Is(err, ErrBlock) {
			t.Fatalf("area %d: %v", a, err)
		}
	}
}

// eofReader returns (len(p), io.EOF) on the last slot, as io.ReaderAt allows.
type eofReader struct{ m *mem }

func (e eofReader) ReadAt(p []byte, off int64) (int, error) {
	n, _ := e.m.ReadAt(p, off)
	if int(off)+n == len(e.m.b) {
		return n, io.EOF
	}
	return n, nil
}

func TestLastSlotMayReturnEOF(t *testing.T) {
	k := keys(t)
	tx := sample(1, slots-1) // the commit entry is the last slot
	m := write(t, k, tx)
	got, err := Recover(k, eofReader{m}, slots, 0)
	if err != nil || got == nil || !equal(got, tx) {
		t.Fatalf("%v %v", got, err)
	}
}

// TestStaleTailSameEpoch: a longer transaction for the SAME target epoch
// (an aborted first attempt) leaves a tail behind a shorter, torn second
// attempt. The tail's records sit at the right positions and epoch but the
// commit hash covers only records 0..n-1, so it must not complete.
func TestStaleTailSameEpoch(t *testing.T) {
	k := keys(t)
	crash := errors.New("crash")
	m := write(t, k, sample(8, 6))
	if err := Write(k, m, slots, sample(8, 2), rand.Reader, func() error { return crash }); err == nil {
		t.Fatal("sync error swallowed")
	}
	// records 0,1 are new; entry 2 is the old record 2, not a commit
	if got, _ := Recover(k, m, slots, 7); got != nil {
		t.Fatal("old tail accepted behind new records")
	}
}
