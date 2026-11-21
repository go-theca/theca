// Package theca is an encrypted container format: authenticated sectors
// (XChaCha20 xor AES-256-CTR, HMAC-SHA-256), a Merkle tree, a write-ahead
// journal, no magic, and keyslots opened by a password, a recovery code and
// hardware factors. See docs/DESIGN.md.
//
// This package is a library over a Backing (a file or block device); it does
// not mount anything.
package theca

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"

	"golang.org/x/crypto/chacha20"

	"github.com/go-theca/theca/internal/format"
	"github.com/go-theca/theca/internal/journal"
	"github.com/go-theca/theca/internal/kdf"
	"github.com/go-theca/theca/internal/lru"
	"github.com/go-theca/theca/internal/merkle"
	"github.com/go-theca/theca/internal/ta1"
)

// SectorSize is the logical sector size.
const SectorSize = ta1.SectorSize

// DefaultJournalEntries is used when CreateOptions leaves it zero.
const DefaultJournalEntries = 64

// Errors.
var (
	// ErrNoMatch is the single answer to "nothing unlocked this": a wrong
	// password, a wrong key, a corrupted slot area and a file that is not a
	// container are indistinguishable (DESIGN 13).
	ErrNoMatch = errors.New("theca: no factor opened a keyslot")
	// ErrCorrupt: the container unlocked but a structure failed to
	// authenticate (both header copies, a tree node, a metadata block).
	ErrCorrupt = errors.New("theca: container is corrupted or was tampered with")
	// ErrSector names a data sector whose tag failed: an I/O error, never
	// silently zero data.
	ErrSector = errors.New("theca: sector failed authentication")
	// ErrRollback: the header is older than the hardware counter allows.
	ErrRollback = errors.New("theca: container is older than the rollback counter (use AcceptRollback to rebind)")
	// ErrCounter: the counter given does not match the one the header names.
	ErrCounter = errors.New("theca: rollback counter missing or not the one recorded in the header")
	// ErrCounterRequired: a counter was asked for (OpenOptions.Counter,
	// CounterFor or CounterDerived) and the header names none: the container
	// was made without one, or an older copy from before `counter rebind` was
	// restored. Asking for a counter means requiring it.
	ErrCounterRequired = errors.New("theca: this container has no rollback counter, but one was asked: an older copy may have been restored")
	ErrRange           = errors.New("theca: offset or length out of range")
	ErrBroken          = errors.New("theca: container failed an earlier write and must be reopened")
	ErrClosed          = errors.New("theca: container is closed")
	ErrNoSlot          = errors.New("theca: no free keyslot")
	ErrOption          = errors.New("theca: invalid option")
	// ErrNoCredential is returned by a FIDO2 provider whose key holds no
	// Theca credential. It is routine during unlock and not an error.
	ErrNoCredential = errors.New("theca: authenticator holds no theca credential")
	// ErrAuthenticator: a FIDO2 provider answered something malformed.
	ErrAuthenticator = errors.New("theca: malformed answer from the authenticator")
)

// Backing is the storage under a container.
type Backing interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Size() (int64, error)
}

// FileBacking adapts an *os.File.
type FileBacking struct{ *os.File }

// Size implements Backing.
func (f FileBacking) Size() (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Counter is a hardware monotonic counter (DESIGN 5.4): in practice a TPM NV
// counter. Handle and Name identify the index; the container pins both.
type Counter interface {
	Handle() uint32
	Name() []byte
	Read() (uint64, error)
	Increment() error
}

// MaxFIDO2Salts is how many salts one hmac-secret request carries (salt1 and
// salt2, CTAP 2.1 §12.5), hence how many partner factors one key pairs with.
const MaxFIDO2Salts = 2

// MaxFIDO2Credentials bounds how many Theca credentials an authenticator
// may report in one answer (a YubiKey 5.7 holds at most 100 discoverable
// credentials). A larger answer is refused, not processed.
const MaxFIDO2Credentials = 128

// FIDO2 is a hmac-secret authenticator holding DISCOVERABLE credentials
// for the rp id "theca" (decision H2, revised: DESIGN 19, I21). Nothing
// about the key is stored in the container: the salts are derived from the
// partner factors (kdf.FIDO2Salt), and the key is asked about all of its
// Theca credentials at once. Each call is one touch and one user
// verification. Every output is the raw 32-byte hmac-secret value.
type FIDO2 interface {
	// Enroll creates a new discoverable credential (rk, credProtect 3) and
	// returns its outputs for each salt, in order (one or two salts).
	Enroll(ctx context.Context, salts [][32]byte) ([][]byte, error)
	// Derive asks for the outputs of EVERY Theca credential on the key, for
	// each salt (getAssertion with an empty allowList, then
	// getNextAssertion): result[i][j] is credential i's output for salts[j].
	// It returns ErrNoCredential if the key holds none.
	Derive(ctx context.Context, salts [][32]byte) ([][][]byte, error)
}

func clearSalts(salts [][32]byte) {
	for i := range salts {
		clear(salts[i][:])
	}
}

// fido2Salts derives one salt per partner factor. A salt is a function of
// the partner's secret: it is a verifier for guesses of that secret, at the
// partner's KDF cost (Argon2id for a password). It goes only to the
// authenticator, and is wiped by the caller (DESIGN 19, I21).
func fido2Salts(partners []Factor) [][32]byte {
	salts := make([][32]byte, len(partners))
	for i := range partners {
		salts[i] = kdf.FIDO2Salt(&partners[i].KEK, partners[i].Kind)
	}
	return salts
}

// checkOutputs validates one credential's answer: one 32-byte output per salt.
func checkOutputs(outs [][]byte, n int) error {
	if len(outs) != n {
		return fmt.Errorf("%w: %d outputs for %d salts", ErrAuthenticator, len(outs), n)
	}
	for _, o := range outs {
		if len(o) != 32 {
			return fmt.Errorf("%w: a %d-byte output", ErrAuthenticator, len(o))
		}
	}
	return nil
}

// Factor is one access factor reduced to a key-encryption key.
type Factor struct {
	Kind string // "pw", "rc", "fido2"
	KEK  [32]byte
}

// Zeroize wipes the factor's key.
func (f *Factor) Zeroize() { clear(f.KEK[:]) }

// PasswordFactor runs Argon2id (one evaluation, D2) with the hinted profile.
func PasswordFactor(hint int, password, salt []byte) (Factor, error) {
	out, err := kdf.Argon2id(hint, password, salt)
	if err != nil {
		return Factor{}, err
	}
	defer clear(out)
	return Factor{Kind: "pw", KEK: kdf.KEK(out, "pw")}, nil
}

// RecoveryFactor parses a printed recovery code.
func RecoveryFactor(code string) (Factor, error) {
	raw, err := format.ParseRecoveryCode(code)
	if err != nil {
		return Factor{}, err
	}
	defer clear(raw)
	return Factor{Kind: "rc", KEK: kdf.KEK(raw, "rc")}, nil
}

// FIDO2Factor turns an hmac-secret output into a factor.
func FIDO2Factor(secret []byte) Factor { return Factor{Kind: "fido2", KEK: kdf.KEK(secret, "fido2")} }

func slotKEK(fs []Factor) ([32]byte, error) {
	switch len(fs) {
	case 1:
		// A key's salt comes from its partner (I21), so a slot opened by the
		// key alone could never be asked for at unlock: refuse to write one.
		if fs[0].Kind == "fido2" {
			return [32]byte{}, fmt.Errorf("%w: a FIDO2 key opens a slot only with a partner factor", ErrOption)
		}
		return fs[0].KEK, nil
	case 2:
		return kdf.Pair(&fs[0].KEK, fs[0].Kind, &fs[1].KEK, fs[1].Kind), nil
	}
	return [32]byte{}, fmt.Errorf("%w: a slot needs one or two factors", ErrOption)
}

// Policy chooses the slots a new container gets.
type Policy int

const (
	// PolicyAny: the password alone, and the recovery code alone, each open
	// the container (1-of-n).
	PolicyAny Policy = iota
	// PolicyTwoOfThree: password + recovery code open it; a hardware factor
	// added later pairs with each of them (DESIGN 6.2, D3).
	PolicyTwoOfThree
)

// CreateOptions configures Create.
type CreateOptions struct {
	Sectors        uint64
	JournalEntries uint32 // 0: DefaultJournalEntries (raised to the minimum)
	Hint           int    // Argon2id profile (D2)
	Password       []byte
	Policy         Policy
	Counter        Counter // optional hardware counter
	// NewCounter, when Counter is nil, makes the counter AFTER the master secret
	// exists, and is given the authValue derived from it (DESIGN 5.4.2): the
	// container records that the counter's authValue is derived, so a mount asks
	// OpenOptions.CounterDerived, not CounterFor. The slice is wiped when
	// NewCounter returns: copy what is kept.
	NewCounter func(auth []byte) (Counter, error)
	Rand       io.Reader // nil: crypto/rand
	CacheBytes int       // see OpenOptions.CacheBytes
}

// OpenOptions configures Open.
type OpenOptions struct {
	Counter Counter
	// CounterFor, when Counter is nil, is asked for the counter once the header
	// has been authenticated and names one (its handle and NV Name are only
	// known then: the header has no plaintext fields). An error it returns
	// refuses the open.
	CounterFor func(handle uint32, name []byte) (Counter, error)
	// CounterDerived is CounterFor for a counter whose authValue is derived from
	// the master secret (the header says so): it is given that authValue, which
	// only someone who unlocked the container has. The slice is wiped when it
	// returns. A container with such a counter and no CounterDerived is refused
	// with ErrCounter.
	CounterDerived func(handle uint32, name, auth []byte) (Counter, error)
	// RebindDerived is RebindFor for a NEW counter with a derived authValue
	// (the migration from a stored one). RebindFor wins if both are set.
	RebindDerived func(handle uint32, name, auth []byte) (Counter, error)
	// RebindFor is the recovery path for a counter that is gone (the index was
	// undefined, the TPM was cleared) or that the container should move away
	// from. It is asked, once the header has authenticated, for a NEW counter:
	// the handle and Name the header records (0 and nil if it records none) are
	// passed so a counter can be made at the same handle. The mount protocol
	// does not run against the old counter: this mount increments the new one,
	// reads its value and binds the header to it. Rollback protection restarts
	// from that moment: nothing is checked against the old counter. Needs the
	// unlocking factors, like any open; the decision to use it is the caller's.
	RebindFor      func(handle uint32, name []byte) (Counter, error)
	AcceptRollback bool
	Rand           io.Reader
	// CacheBytes bounds the memory the container keeps for verified, clean
	// metadata blocks and tree nodes (half each, 4 KiB per entry): 0 is
	// DefaultCacheBytes. Entries that are part of a transaction not yet
	// committed are not counted: the journal budget bounds those. An evicted
	// entry is wiped, and read and authenticated again when it is needed.
	CacheBytes int
}

// DefaultCacheBytes is the cache budget when none is given: 64 MiB, which
// holds 8192 metadata blocks (each covering 64 sectors: 2 GiB of volume) and
// 8192 tree nodes.
const DefaultCacheBytes = 64 << 20

// minCacheEntries keeps a tiny budget workable: a write needs a few blocks at
// once.
const minCacheEntries = 8

// newCaches builds the metadata block cache and the Merkle tree, both bounded
// by cacheBytes.
func (c *Container) newCaches(root [32]byte) {
	n := c.cacheBytes
	if n <= 0 {
		n = DefaultCacheBytes
	}
	entries := max(n/2/4096, minCacheEntries)
	c.meta = lru.New(entries, func(m uint64) bool { _, d := c.dMeta[m]; return d },
		func(b *[4096]byte) { clear(b[:]) })
	c.tree = merkle.New(c.k, c.geo.Shape, root, nodeStore{c})
	c.tree.SetCacheLimit(entries)
}

// Unlock carries the factors the user presents.
type Unlock struct {
	Hint     int
	Password []byte
	Recovery string
	FIDO     FIDO2
}

// Info describes an open container.
type Info struct {
	Sectors             uint64
	Size                uint64
	Epoch               uint64
	SlotsUsed           int
	RollbackProtected   bool
	CounterHandle       uint32 // the counter's handle; 0 when RollbackProtected is false
	CounterTPM          []byte // identity of the TPM the counter is pinned to; nil when RollbackProtected is false or the container predates the pin
	CounterDerivedAuth  bool   // the counter's authValue is derived from the master secret (DESIGN 5.4.2); false when RollbackProtected is false
	JournalEntries      uint32
	ReplayedTransaction bool
}

// Container is an open container. It is safe for concurrent use.
type Container struct {
	mu         sync.Mutex
	f          Backing
	rng        io.Reader
	geo        format.Geometry
	body       format.Body
	k          *ta1.Keys
	tree       *merkle.Tree
	cacheBytes int
	meta       *lru.Cache[*[4096]byte] // verified metadata blocks: a bounded LRU of clean ones, dirty ones pinned
	dMeta      map[uint64]struct{}
	dData      map[uint64][]byte
	broken     error
	closed     bool
	info       Info
}

type region struct {
	f   Backing
	off int64
}

func (r region) ReadAt(p []byte, off int64) (int, error)  { return r.f.ReadAt(p, r.off+off) }
func (r region) WriteAt(p []byte, off int64) (int, error) { return r.f.WriteAt(p, r.off+off) }

type nodeStore struct{ c *Container }

func (n nodeStore) LoadNode(ord uint64) ([]byte, error) {
	b := make([]byte, merkle.NodeSize)
	if _, err := n.c.f.ReadAt(b, int64(n.c.geo.TreeOff+ord*merkle.NodeSize)); err != nil {
		return nil, err
	}
	return b, nil
}

func randOr(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// fillRandom writes a ChaCha20 keystream (key from rng) over [0, size).
func fillRandom(f Backing, size uint64, rng io.Reader) error {
	var kn [44]byte
	if _, err := io.ReadFull(rng, kn[:]); err != nil {
		return fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	c, _ := chacha20.NewUnauthenticatedCipher(kn[:32], kn[32:])
	buf := make([]byte, 1<<20)
	for off := uint64(0); off < size; off += uint64(len(buf)) {
		n := min(uint64(len(buf)), size-off)
		clear(buf[:n])
		c.XORKeyStream(buf[:n], buf[:n])
		if _, err := f.WriteAt(buf[:n], int64(off)); err != nil {
			return err
		}
	}
	return nil
}

// Create formats a new container in f. It returns the container and, for
// both policies, the printed recovery code (shown once, never stored).
func Create(f Backing, o CreateOptions) (c *Container, printed string, err error) {
	rng := randOr(o.Rand)
	jn := o.JournalEntries
	if jn == 0 {
		jn = DefaultJournalEntries
	}
	shape, err := merkle.NewShape(max(o.Sectors, 1))
	if err != nil || o.Sectors == 0 {
		return nil, "", fmt.Errorf("%w: sectors %d", ErrOption, o.Sectors)
	}
	jn = max(jn, format.MinJournal(shape))
	geo, err := format.NewGeometry(o.Sectors, jn)
	if err != nil {
		return nil, "", err
	}
	if len(o.Password) == 0 {
		return nil, "", fmt.Errorf("%w: empty password", ErrOption)
	}
	if o.Policy != PolicyAny && o.Policy != PolicyTwoOfThree {
		return nil, "", fmt.Errorf("%w: policy %d", ErrOption, o.Policy)
	}

	ms, err := ta1.Generate(rng)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil {
			ms.Zeroize() // review of PR #4, finding 5
		}
	}()
	var cid [16]byte
	var salt [format.SaltSize]byte
	if _, err := io.ReadFull(rng, cid[:]); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	if _, err := io.ReadFull(rng, salt[:]); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
	}
	pw, err := PasswordFactor(o.Hint, o.Password, salt[:])
	if err != nil {
		return nil, "", err
	}
	defer pw.Zeroize()
	rawRC, printed, err := format.NewRecoveryCode(rng)
	if err != nil {
		return nil, "", err
	}
	rc := Factor{Kind: "rc", KEK: kdf.KEK(rawRC, "rc")}
	clear(rawRC)
	defer rc.Zeroize()

	if err := fillRandom(f, geo.End, rng); err != nil {
		return nil, "", err
	}
	if err := trunc(f, geo.End); err != nil {
		return nil, "", err
	}
	if _, err := f.WriteAt(salt[:], 0); err != nil {
		return nil, "", err
	}

	c = &Container{f: f, rng: rng, geo: geo, k: ms,
		dMeta: map[uint64]struct{}{}, dData: map[uint64][]byte{}}
	c.body = format.Body{CID: cid, Sectors: o.Sectors, JournalEntries: jn,
		Root: merkle.EmptyRoot(ms, geo.Shape)}
	c.cacheBytes = o.CacheBytes
	c.newCaches(c.body.Root)

	var specs [][]Factor
	switch o.Policy {
	case PolicyAny:
		specs = [][]Factor{{pw}, {rc}}
	case PolicyTwoOfThree:
		specs = [][]Factor{{pw, rc}}
	}
	// No header exists yet, so the order of slot and header writes does not
	// matter here: a crash leaves something that is not a container.
	for _, s := range specs {
		p, err := c.sealSlot(s)
		if err != nil {
			return nil, "", err
		}
		if err := c.writeSlot(p.i, p.blob); err != nil {
			return nil, "", err
		}
	}
	ctr, derived := o.Counter, false
	if ctr == nil && o.NewCounter != nil {
		auth := kdf.CounterAuth(ms)
		ctr, err = o.NewCounter(auth)
		clear(auth)
		if err != nil {
			return nil, "", err
		}
		derived = true
	}
	if ctr != nil {
		id, err := identityOf(ctr) // before the increment: no identity, no counter moved
		if err != nil {
			return nil, "", err
		}
		if err := ctr.Increment(); err != nil {
			return nil, "", err
		}
		c0, err := ctr.Read()
		if err != nil {
			return nil, "", err
		}
		c.body.Counter = &format.Counter{Handle: ctr.Handle(), Name: ctr.Name(), Bound: c0, TPMID: id, DerivedAuth: derived}
		c.info.RollbackProtected = true
		c.info.CounterHandle = ctr.Handle()
	}
	if err := c.writeHeader(); err != nil {
		return nil, "", err
	}
	if err := f.Sync(); err != nil {
		return nil, "", err
	}
	c.fillInfo()
	return c, printed, nil
}

// trunc grows a backing that supports it so a fresh file has its size.
func trunc(f Backing, size uint64) error {
	if t, ok := f.(interface{ Truncate(int64) error }); ok {
		cur, err := f.Size()
		if err != nil {
			return err
		}
		if uint64(cur) > size {
			return t.Truncate(int64(size))
		}
	}
	return nil
}

func (c *Container) fillInfo() {
	n := 0
	for i := 0; i < format.NumSlots; i++ {
		if c.body.SlotsUsed&(1<<i) != 0 {
			n++
		}
	}
	c.info.Sectors = c.body.Sectors
	c.info.Size = c.body.Sectors * SectorSize
	c.info.Epoch = c.body.Epoch
	c.info.SlotsUsed = n
	c.info.JournalEntries = c.body.JournalEntries
	c.info.RollbackProtected = c.body.Counter != nil
	c.info.CounterHandle = 0
	c.info.CounterTPM = nil
	c.info.CounterDerivedAuth = false
	if c.body.Counter != nil {
		c.info.CounterDerivedAuth = c.body.Counter.DerivedAuth
		c.info.CounterHandle = c.body.Counter.Handle
		c.info.CounterTPM = c.body.Counter.TPMID
	}
}

func (c *Container) freeSlots() []int {
	var free []int
	for i := 0; i < format.NumSlots; i++ {
		if c.body.SlotsUsed&(1<<i) == 0 {
			free = append(free, i)
		}
	}
	return free
}

// freeSlot picks a random unused slot index.
func (c *Container) freeSlot() (int, error) {
	free := c.freeSlots()
	if len(free) == 0 {
		return 0, ErrNoSlot
	}
	// Rejection sampling for an unbiased choice. A draw is rejected with
	// probability below 1/2, so 64 rejections in a row from a working source
	// happen with probability below 2^-64: past that the source is broken
	// (or a caller-supplied Rand is constant) and looping would never end.
	var b [1]byte
	for range 64 {
		if _, err := io.ReadFull(c.rng, b[:]); err != nil {
			return 0, fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
		}
		if int(b[0]) < 256/len(free)*len(free) { // unbiased
			return free[int(b[0])%len(free)], nil
		}
	}
	return 0, fmt.Errorf("%w: 64 rejected draws in a row", ta1.ErrNoRand)
}

func (c *Container) writeSlot(i int, blob []byte) error {
	_, err := c.f.WriteAt(blob, int64(format.SlotsOff+i*format.SlotSize))
	return err
}

// pendingSlot is a sealed slot whose index is reserved in the body but whose
// bytes are not on disk yet.
type pendingSlot struct {
	i    int
	blob []byte
}

// sealSlot seals a wrap slot for the factors into a free index and reserves
// that index in the body. Nothing is written.
func (c *Container) sealSlot(fs []Factor) (pendingSlot, error) {
	kek, err := slotKEK(fs)
	if err != nil {
		return pendingSlot{}, err
	}
	defer clear(kek[:])
	i, err := c.freeSlot()
	if err != nil {
		return pendingSlot{}, err
	}
	blob, err := format.SealWrap(c.k, &kek, i, c.rng)
	if err != nil {
		return pendingSlot{}, err
	}
	c.body.SlotsUsed |= 1 << i
	return pendingSlot{i, blob}, nil
}

// publishLocked records the reserved slots in the header (one commit), and
// only then writes their bytes. A crash in between leaves a slot that is
// recorded but holds random bytes: harmless, and RemoveSlot clears it.
// The opposite order would leave a working slot the header does not record,
// which nothing could list or remove (review of PR #4, finding 3).
func (c *Container) publishLocked(why string, ps []pendingSlot) error {
	if err := c.commitLocked(why); err != nil {
		return err
	}
	for _, p := range ps {
		if err := c.writeSlot(p.i, p.blob); err != nil {
			return c.fail(err)
		}
	}
	if err := c.f.Sync(); err != nil {
		return c.fail(err)
	}
	return nil
}

// writeHeader seals the current body into copy epoch%2. The copy holding the
// previous epoch is never touched (DESIGN 10.5).
func (c *Container) writeHeader() error {
	blob, err := format.SealHeader(c.k, &c.body, c.rng)
	if err != nil {
		return err
	}
	_, err = c.f.WriteAt(blob, int64(c.geo.Header(c.body.Epoch)))
	return err
}

// AddSlot adds a slot opened by the given one or two factors.
func (c *Container) AddSlot(fs ...Factor) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	saved := c.body.SlotsUsed
	p, err := c.sealSlot(fs)
	if err != nil {
		c.body.SlotsUsed = saved
		return err
	}
	return c.publishLocked("add slot", []pendingSlot{p})
}

// RemoveSlot overwrites slot i with random bytes, then records it as free.
// Any index 0..15 is accepted, recorded or not, so that a working slot the
// header does not record (left by a crash in an older version, or written
// by another tool) can still be destroyed. The overwrite comes first: a
// crash in between leaves a recorded slot holding random bytes, never a
// working slot marked free (review of PR #4, finding 3).
//
// It only stops access to the CURRENT container: anyone holding an older
// copy can still open that copy with the revoked factor, because the master
// secret does not change (DESIGN 2, review finding R7). Callers must tell
// the user.
func (c *Container) RemoveSlot(i int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	if i < 0 || i >= format.NumSlots {
		return fmt.Errorf("%w: slot %d out of range", ErrOption, i)
	}
	return c.removeSlotLocked(i)
}

// removeSlotLocked is RemoveSlot for an index already checked.
func (c *Container) removeSlotLocked(i int) error {
	junk, err := format.RandomSlot(c.rng)
	if err != nil {
		return err
	}
	if err := c.writeSlot(i, junk); err != nil {
		return c.fail(err)
	}
	if err := c.f.Sync(); err != nil {
		return c.fail(err)
	}
	if c.body.SlotsUsed&(1<<i) == 0 {
		return nil
	}
	c.body.SlotsUsed &^= 1 << i
	return c.commitLocked("remove slot")
}

// EnrollFIDO2 enrols a hardware key paired with each of the given partner
// factors (one or two: the hmac-secret salts of one request). The key makes a
// new discoverable credential and answers one output per partner, for the
// salt derived from that partner (kdf.FIDO2Salt); each output becomes the
// pairwise slot {partner, key}. Nothing else is stored, and all the slots are
// recorded by ONE commit. Enrolment needs the master secret, so the container
// must already be open. The container and its free slots are checked before
// the key is asked, so a touch is never spent on an enrolment that cannot be
// stored (review of PR #4, finding 6).
func (c *Container) EnrollFIDO2(ctx context.Context, dev FIDO2, partners ...Factor) error {
	if len(partners) == 0 || len(partners) > MaxFIDO2Salts {
		return fmt.Errorf("%w: a key pairs with 1 or %d partner factors, not %d", ErrOption, MaxFIDO2Salts, len(partners))
	}
	c.mu.Lock()
	err := c.usable()
	if err == nil && len(c.freeSlots()) < len(partners) {
		err = ErrNoSlot
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	// The lock is not held while the key waits for a touch.
	salts := fido2Salts(partners) // password-equivalent: wiped, never logged
	defer clearSalts(salts)
	outs, err := dev.Enroll(ctx, salts)
	defer func() {
		for _, o := range outs {
			clear(o)
		}
	}()
	if err != nil {
		return err
	}
	if err := checkOutputs(outs, len(partners)); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	saved := c.body.SlotsUsed
	var ps []pendingSlot
	for i := range partners {
		key := FIDO2Factor(outs[i])
		w, err := c.sealSlot([]Factor{partners[i], key})
		key.Zeroize()
		if err != nil {
			c.body.SlotsUsed = saved
			return err
		}
		ps = append(ps, w)
	}
	return c.publishLocked("enrol fido2", ps)
}

func (c *Container) usable() error {
	if c.closed {
		return ErrClosed
	}
	return c.broken
}

func (c *Container) fail(err error) error {
	if c.broken == nil {
		c.broken = fmt.Errorf("%w: %v", ErrBroken, err)
	}
	return err
}

// Info returns a snapshot.
func (c *Container) Info() Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

// Size is the logical size in bytes.
func (c *Container) Size() int64 { return int64(c.body.Sectors * SectorSize) }

// ---- sectors ---------------------------------------------------------------

func (c *Container) freshMeta(m uint64) (*[4096]byte, error) {
	blk := new([4096]byte)
	for e := uint64(0); e < merkle.MetaPerBlock; e++ {
		ent := blk[e*64 : (e+1)*64]
		if _, err := io.ReadFull(c.rng, ent[:ta1.SeedSize]); err != nil {
			return nil, fmt.Errorf("%w: %v", ta1.ErrNoRand, err)
		}
		t := c.k.UnwrittenTag(&c.body.CID, m*merkle.MetaPerBlock+e, (*[ta1.SeedSize]byte)(ent[:ta1.SeedSize]))
		copy(ent[ta1.SeedSize:], t[:])
	}
	return blk, nil
}

// loadMeta returns the verified metadata block m, or nil if it was never
// written.
func (c *Container) loadMeta(m uint64) (*[4096]byte, error) {
	if b, ok := c.meta.Get(m); ok {
		return b, nil
	}
	v, err := c.tree.Meta(m)
	if err != nil {
		return nil, c.treeErr(err)
	}
	if v == c.tree.Default() {
		return nil, nil
	}
	b := new([4096]byte)
	if _, err := c.f.ReadAt(b[:], int64(c.geo.MetaOff+m*4096)); err != nil {
		return nil, err
	}
	if got := merkle.N1(c.k, b[:]); !hmac.Equal(got[:], v[:]) {
		return nil, fmt.Errorf("%w: metadata block %d", ErrCorrupt, m)
	}
	c.meta.Put(m, b)
	return b, nil
}

func (c *Container) treeErr(err error) error {
	if errors.Is(err, merkle.ErrTamper) {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return err
}

func (c *Container) readSector(s uint64, dst []byte) error {
	m, e := s/merkle.MetaPerBlock, s%merkle.MetaPerBlock
	blk, err := c.loadMeta(m)
	if err != nil {
		return err
	}
	if blk == nil {
		clear(dst)
		return nil
	}
	ent := blk[e*64 : (e+1)*64]
	seed := (*[ta1.SeedSize]byte)(ent[:ta1.SeedSize])
	tag := (*[ta1.SectorTagSize]byte)(ent[ta1.SeedSize:])
	if un := c.k.UnwrittenTag(&c.body.CID, s, seed); hmac.Equal(un[:], tag[:]) {
		clear(dst)
		return nil
	}
	ct, ok := c.dData[s]
	if !ok {
		ct = make([]byte, SectorSize)
		if _, err := c.f.ReadAt(ct, int64(c.geo.DataOff+s*SectorSize)); err != nil {
			return err
		}
	}
	if err := c.k.OpenSector(&c.body.CID, s, dst, ct, seed, tag); err != nil {
		return fmt.Errorf("%w: sector %d", ErrSector, s)
	}
	return nil
}

func (c *Container) writeSector(s uint64, plain []byte) error {
	// Commit first if this write could overflow the journal.
	items := len(c.dData) + len(c.dMeta) + c.tree.DirtyCount()
	if items+2+c.geo.Shape.Levels() > int(c.geo.JournalEntries)-1 {
		if err := c.commitLocked("journal budget"); err != nil {
			return err
		}
	}
	m, e := s/merkle.MetaPerBlock, s%merkle.MetaPerBlock
	old, err := c.loadMeta(m)
	if err != nil {
		return err
	}
	blk := new([4096]byte)
	if old == nil {
		if fresh, err := c.freshMeta(m); err != nil {
			return err
		} else {
			blk = fresh
		}
	} else {
		*blk = *old
	}
	ct := make([]byte, SectorSize)
	seed, tag, err := c.k.SealSector(&c.body.CID, s, ct, plain, c.rng)
	if err != nil {
		return err
	}
	copy(blk[e*64:], seed[:])
	copy(blk[e*64+ta1.SeedSize:], tag[:])
	if err := c.tree.SetMeta(m, merkle.N1(c.k, blk[:])); err != nil {
		return c.treeErr(err)
	}
	c.dMeta[m] = struct{}{} // pinned before it is stored, so it can never be evicted
	c.meta.Put(m, blk)
	c.dData[s] = ct
	return nil
}

// ReadAt implements io.ReaderAt over the logical volume.
func (c *Container) ReadAt(p []byte, off int64) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return 0, err
	}
	size := c.body.Sectors * SectorSize
	if off < 0 {
		return 0, ErrRange
	}
	if len(p) == 0 {
		return 0, nil
	}
	if uint64(off) >= size {
		return 0, io.EOF
	}
	want := min(uint64(len(p)), size-uint64(off))
	var sec [SectorSize]byte
	var done uint64
	for done < want {
		pos := uint64(off) + done
		s, in := pos/SectorSize, pos%SectorSize
		if err := c.readSector(s, sec[:]); err != nil {
			return int(done), err
		}
		done += uint64(copy(p[done:want], sec[in:]))
	}
	if want < uint64(len(p)) {
		return int(done), io.EOF
	}
	return int(done), nil
}

// WriteAt implements io.WriterAt. Writes past the end are refused.
func (c *Container) WriteAt(p []byte, off int64) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return 0, err
	}
	size := c.body.Sectors * SectorSize
	if off < 0 || uint64(off)+uint64(len(p)) > size {
		return 0, ErrRange
	}
	var sec [SectorSize]byte
	var done uint64
	for done < uint64(len(p)) {
		pos := uint64(off) + done
		s, in := pos/SectorSize, pos%SectorSize
		n := min(uint64(SectorSize-in), uint64(len(p))-done)
		if n < SectorSize {
			if err := c.readSector(s, sec[:]); err != nil {
				return int(done), err
			}
		}
		copy(sec[in:], p[done:done+n])
		if err := c.writeSector(s, sec[:]); err != nil {
			return int(done), err
		}
		done += n
	}
	return int(done), nil
}

// ---- commit and recovery ---------------------------------------------------

func (c *Container) dirty() bool {
	return len(c.dData) > 0 || len(c.dMeta) > 0 || c.tree.DirtyCount() > 0
}

func sortedKeys[V any](m map[uint64]V) []uint64 {
	k := make([]uint64, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	slices.Sort(k)
	return k
}

// commitLocked makes every pending change durable as one journaled
// transaction that moves the epoch from e to e+1, then writes the header
// copy for e+1 (DESIGN 5.3). It always runs, even with nothing dirty: header
// changes (slots, counter binding) ride on the same epoch step. Any failure
// leaves the in-memory state unusable until reopen, where recovery decides.
func (c *Container) commitLocked(why string) error {
	tx := &journal.Tx{Epoch: c.body.Epoch + 1, Root: c.tree.Root()}
	for _, s := range sortedKeys(c.dData) {
		tx.Records = append(tx.Records, journal.Record{Area: journal.AreaData, Index: s, Data: c.dData[s]})
	}
	for _, m := range sortedKeys(c.dMeta) {
		blk, _ := c.meta.Peek(m) // dirty: pinned, always cached
		tx.Records = append(tx.Records, journal.Record{Area: journal.AreaMeta, Index: m, Data: blockBytes(blk)})
	}
	for _, o := range c.tree.Dirty() {
		tx.Records = append(tx.Records, journal.Record{Area: journal.AreaNode, Index: o, Data: c.tree.Bytes(o)})
	}
	jr := region{c.f, int64(c.geo.JournalOff)}
	if err := journal.Write(c.k, jr, c.body.JournalEntries, tx, c.rng, c.f.Sync); err != nil {
		return c.fail(fmt.Errorf("%s: journal: %w", why, err))
	}
	if err := c.apply(tx); err != nil {
		return c.fail(fmt.Errorf("%s: apply: %w", why, err))
	}
	if err := c.f.Sync(); err != nil {
		return c.fail(err)
	}
	c.body.Epoch = tx.Epoch
	c.body.Root = tx.Root
	if err := c.writeHeader(); err != nil {
		return c.fail(err)
	}
	if err := c.f.Sync(); err != nil {
		return c.fail(err)
	}
	clear(c.dData)
	clear(c.dMeta)
	c.tree.ClearDirty()
	c.fillInfo()
	return nil
}

// blockBytes slices a cached block. It is a function of its own, not inlined,
// because slicing the generic cache's *[4096]byte result inline makes the Go
// 1.27.3 compiler stop with "internal compiler error: bad ptr to array in
// slice go.shape.*uint8".
//
//go:noinline
func blockBytes(b *[4096]byte) []byte { return b[:] }

// apply writes a transaction's blocks to their destinations. The indexes of
// a replayed transaction are range-checked here, though they came from
// authenticated records.
func (c *Container) apply(tx *journal.Tx) error {
	for _, r := range tx.Records {
		var off uint64
		switch r.Area {
		case journal.AreaData:
			if r.Index >= c.geo.Sectors {
				return fmt.Errorf("%w: data index %d", ErrCorrupt, r.Index)
			}
			off = c.geo.DataOff + r.Index*SectorSize
		case journal.AreaMeta:
			if r.Index >= c.geo.Shape.MetaBlocks {
				return fmt.Errorf("%w: metadata index %d", ErrCorrupt, r.Index)
			}
			off = c.geo.MetaOff + r.Index*4096
		default:
			if r.Index >= c.geo.Shape.NodeCount() {
				return fmt.Errorf("%w: node index %d", ErrCorrupt, r.Index)
			}
			off = c.geo.TreeOff + r.Index*merkle.NodeSize
		}
		if _, err := c.f.WriteAt(r.Data, int64(off)); err != nil {
			return err
		}
	}
	return nil
}

// Sync commits pending writes.
func (c *Container) Sync() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	if !c.dirty() {
		return c.f.Sync()
	}
	return c.commitLocked("sync")
}

// Close commits, wipes the keys and refuses further use. The backing is not
// closed: it belongs to the caller.
func (c *Container) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	var err error
	if c.broken == nil && c.dirty() {
		err = c.commitLocked("close")
	}
	c.closed = true
	c.k.Zeroize()
	// Wipe what was cached: verified metadata blocks and tree nodes.
	c.meta.Clear()
	c.tree.Wipe()
	return err
}

// Verify reads every sector, authenticating tags, metadata blocks and the
// tree. It returns the number of sectors checked and the first failure.
func (c *Container) Verify() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return 0, err
	}
	var sec [SectorSize]byte
	for s := uint64(0); s < c.body.Sectors; s++ {
		if err := c.readSector(s, sec[:]); err != nil {
			return s, err
		}
	}
	return c.body.Sectors, nil
}
