# Theca — design document

Status: **reviewed design, decisions D1–D7 taken**, 2026-11-15. No code exists yet. Nothing here is a
commitment until a v0.1 tag says so.

Theca is an encrypted container format (a file or a block device that holds a
volume) written in pure Go (`CGO_ENABLED=0`). The goal is a format that is
better than the state of the art in **composition** — how known, analysed
primitives are put together — while inventing **no primitive and no mode**.
Every construction below is either a published one used as published, or a
generic composition whose security argument is a standard reduction that we
state explicitly so that a reviewer can check it.

Conventions. "Opened" in the bibliography (section 16) means the text was read
for this document; anything cited from memory is listed separately as **not
opened** and must be read before the relevant phase starts. MUST/SHOULD are
used in the RFC 2119 sense only inside the format sketch (section 10).
Decisions D1–D7 were taken by the user on 2026-11-15 and are recorded in
section 15.

---

## 0. Summary of the proposal

| Concern | v0.1 choice | Later |
|---|---|---|
| Sector encryption | **Authenticated profile "Theca-A"**: per-write random 40-byte seed, keystream = XChaCha20 ⊕ AES-256-CTR under independent keys, Encrypt-then-MAC with HMAC-SHA-256 | Length-preserving profile "Theca-L" with HCTR2 (single family, documented as weaker) |
| Cascade | **On by default** (D1, decided) | Single-family "fast" suite only if measurements demand it |
| Integrity | Per-sector tag + 128-ary Merkle tree, root in the encrypted header | Log-structured layout to drop the journal's 2× write cost |
| Crash consistency | Write-ahead journal (dm-integrity "J" mode semantics) | CoW / log-structured |
| Rollback | Epoch in header, checked against a TPM 2.0 NV counter where available | Remote witness; macOS has no counter we can reach |
| KDF | Argon2id, RFC 9106 §4 parameters from a **fixed table, never read from disk** | asmgen NEON BlaMka kernel |
| Access | Password slot + printed recovery code; 2-of-3 (password, hardware, recovery) via pairwise slots (D3); every slot sealed with TA1 | FIDO2 `hmac-secret` (YubiKey Bio), Secure Enclave factors |
| Rollback granularity | TPM counter bumped once per mount session; NV Name pinned in the header | Remote witness |
| Revocation | Documented limit: old snapshots stay openable with a revoked factor | MS rotation with re-encryption (v0.3) |
| Post-quantum | — (D4: v0.2, uniform encoding) | HPKE (RFC 9180) with `MLKEM768-X25519` (X-Wing), already in Go's `crypto/hpke`, export-only then TA1 |
| Header | No magic, random-looking, trial decryption, key-committing | Kemeleon + Elligator 2 so recipient slots stay uniform |
| Deniability ("Palimpsest") | Not in v0.1 | Research track: write-only ORAM (HIVE → DataLair → PD-DM lineage) |

---

## 1. Threat model (global)

Adversaries, from weakest to strongest. Each section below says which ones it
addresses.

- **A1 — single snapshot.** Obtains one copy of the container at rest (lost
  laptop, seized disk, cloud copy). Unlimited offline computation within
  classical (and, for long-lived data, quantum) bounds.
- **A2 — multi-snapshot, passive.** Obtains several copies over time (border
  crossings, cloud sync history, APFS/ZFS snapshots, backups) and compares them.
- **A3 — active offline.** Modifies the container between two uses by the
  owner: flips bits, swaps sectors, splices sectors from older copies.
- **A4 — rollback.** Replaces the whole container (or the whole header) by an
  older, genuine copy.
- **A5 — coercion.** Can compel the owner to reveal *a* password and wants to
  know whether more data exists (deniability).
- **A6 — harvest now, decrypt later.** Records public-key-wrapped material
  today, attacks it with a quantum computer later.

Out of scope for every phase: an adversary that controls the host while the
container is mounted (keys are in memory), hardware fault injection, and
physical side channels on the host. Timing side channels in our own code are
in scope (section 13).

---

## 2. Key hierarchy

```
                 master secret MS = Kc ‖ Ka ‖ Km     (3 × 256 bits, from crypto/rand,
                                                      drawn independently)
   Kc  XChaCha20 keystream key ─┐
   Ka  AES-256-CTR key        ──┼─ Theca-A (§4): sectors, journal records,
   Km  HMAC-SHA-256 key       ──┘  header body; Km also keys the Merkle tree (§5)

   MS is never stored. It is reconstructed from access factors (§6):
     - 1-of-n slots: each slot wraps MS under a key-encryption key (KEK);
     - 2-of-3 policy: MS is Shamir-split; each share is wrapped by one factor.
```

The three keys are **independent random draws**, not outputs of one KDF. The
cascade argument (§3) needs independent keys. Deriving them from a single seed
with HKDF would make the independence computational and would put SHA-256 under
both layers. Shamir splitting works bytewise, so splitting 96 bytes costs the
same as splitting 32. Sectors, journal records and the header body use the same
three keys. They are separated by the per-object random seed `r` (§4.3) and by
distinct MAC labels, so no separate header key is needed.

HKDF-SHA-256 (RFC 5869, Go `crypto/hkdf`) is used only at the wrapping layer.
It derives key-encryption keys from factor outputs, and it expands each 32-byte
KEK into the three Theca-A keys that seal a slot (§6.2), with `info` strings
that bind the format version and suite (§9.3). Wrapping keys are therefore only
*computationally* independent. That is accepted because the wrapped object is
short and is sealed with TA1 itself, so both cipher families still protect it
(review finding R4).

**Revocation and snapshots.** Removing a slot or a recovery code only stops
access to the *current* container. An adversary holding an older snapshot (A2)
can still open that snapshot with the revoked factor, and because MS never
changes, the snapshot's keys are the current keys. Real revocation needs **MS
rotation**: a fresh MS and a re-encryption of every written sector, done
online and tracked in the header. This is planned for v0.3 (§14) and the CLI
must say so whenever a slot is removed (review finding R7).

---

## 3. Goal 1 — cascade of unrelated families

### 3.1 Primary source and what it proves

Maurer and Massey, *Cascade ciphers: the importance of being first* (J.
Cryptology 6(1), 1993). Only the abstract and first page were read (the
Springer PDF is paywalled; see §15). The abstract states: for very general
notions of breaking a cipher, a cascade with independently keyed components
is at least as hard to break as its **first** component; if the components
**commute**, the cascade is at least as hard as the **hardest** component; and
**additive stream ciphers commute**, which the authors propose as a design
strategy.

Theca uses exactly that strategy: the two layers are additive stream ciphers,

```
C = P ⊕ XChaCha20(Kc, Nc) ⊕ AES-256-CTR(Ka, Na)
```

so the order question that motivates the paper's title does not arise.

### 3.2 The reduction we rely on (indistinguishability model)

Stated so a reviewer can check it. Let `F` and `G` be keystream generators
indexed by nonce, with independent keys. Claim: if `F` is a PRF (outputs
indistinguishable from random for distinct nonces) **or** `G` is, then
`F ⊕ G` is a PRF. Proof sketch: if `F` is a PRF, an adversary against `F ⊕ G`
is turned into one against `F` by drawing `G`'s key itself and XORing `G`'s
output into each oracle answer. When the oracle is truly random, `random ⊕ G`
is random. The case for `G` is symmetric. Advantage of `F ⊕ G` is at most
`min(Adv_F, Adv_G)` plus nonce-collision terms (§4.3). This is the standard
XOR combiner. It needs the keys to be **independent** (§2) and the nonces to be
**distinct per key** (§4.3).

For wide-block (length-preserving) ciphers the analogous statement holds for
the tweakable SPRP notion. If `E1` is an SPRP, replace it with a random
permutation. `E2` composed with a random permutation is a random permutation,
and the adversary simulates `E2` and its inverse with `E2`'s own key. The
symmetric argument covers `E2`. Maurer–Massey's "first" caveat applies to
their more general breaking notions, not to this one. §4.5 shows why we still
cannot use this for a length-preserving cascade.

### 3.3 Why AES + ChaCha, and comparison with VeraCrypt

VeraCrypt offers ten cascades of 2 or 3 block ciphers, all in XTS mode, all
SPN or Feistel (AES, Serpent, Twofish, Camellia, Kuznyechik), each with its own
independent key (VeraCrypt documentation, "Cascades", opened). Two weaknesses:

1. **Correlated design families.** AES, Serpent, Camellia and Kuznyechik are
   all substitution–permutation networks with 128-bit blocks. Twofish is a
   Feistel network. A structural advance that hurts SPNs (algebraic,
   integral, or a future quantum-structural attack) may hurt several layers at
   once. AES (SPN, S-box non-linearity) and ChaCha (ARX, non-linearity from
   modular addition) have no shared component, and their cryptanalytic records
   are independent.
2. **XTS in every layer.** A cascade of XTS layers is still deterministic per
   (sector, 16-byte position) and still malleable at 16-byte granularity
   (§4.1). Cascading does not repair a mode-level property.

### 3.4 Optional or default?

**Recommendation: default on, with one suite in v0.1.** Reasons:

- A second suite doubles the test matrix and creates the agility surface that
  §9.4 tries to keep small.
- The estimated cost (§11) is bounded by the slower layer (ChaCha20) plus
  HMAC. On hardware with AES instructions the AES-CTR layer adds roughly 15–25%
  to the cost of the ChaCha layer alone. These are *estimates*: measurement
  was deferred because of host load (§11.3).
- The point of Theca is to be "better than state of the art". A single-family
  default would make it XChaCha20 + HMAC with a nicer header.

**Decided (D1):** the cascade is on by default.

### 3.5 Threat model, costs, open questions

- Addresses: A1/A2 confidentiality against a break of **one** family.
- Does **not** address: a break of HMAC-SHA-256 (integrity), of Argon2id or of
  the access factors. Those are single points. The MAC is a third family
  (Merkle–Damgård), chosen so that integrity does not fail with either
  encryption layer.
- Cost: one extra keystream per byte; 32 bytes more key material.
- **Q1.1** Should the MAC also be a combiner (HMAC-SHA-256 ‖ KMAC256, which is
  unforgeable if either is)? It adds 24–32 bytes per sector and a Keccak pass.
  Proposed answer: no for v0.1; revisit if SHA-2 weakens.
- **Q1.2** XChaCha20 (20 rounds) or XChaCha12 as in Adiantum? We propose 20.
  With AES alongside it, 12 rounds would be defensible, but it would be a
  second, unreviewed parameter choice.

---

## 4. Goal 2 — sector encryption: authenticated vs wide-block

### 4.1 XTS (IEEE 1619 / NIST SP 800-38E)

SP 800-38E (opened) approves XTS-AES "for protecting the confidentiality of
data on storage devices" and states "the mode does not provide authentication
of the data or its source". IEEE 1619-2007 itself was **not opened**
(paywalled). Properties that follow from the construction (XEX with a
per-block tweak):

- **deterministic**: the same plaintext at the same (sector, block) position
  always gives the same ciphertext. A2 sees which 16-byte blocks changed
  between snapshots;
- **malleable at 16-byte granularity**: A3 can replace one 16-byte ciphertext
  block, which randomises exactly the corresponding 16 plaintext bytes and
  leaves the rest of the sector intact; or A3 can restore an older 16-byte
  block at the same position;
- no integrity, no freshness.

### 4.2 HCTR2

Crowley, Huckleberry, Biggers, *Length-preserving encryption with HCTR2*
(ePrint 2021/1441; read from the authors' LaTeX source in google/hctr2,
`paper/specification.tex` and `paper/security.tex`).

- Construction (§Specification): POLYVAL hash `H_h(T, M)` over the tweak and
  message, XCTR stream mode `XCTR_k(S) = E_k(S ⊕ 1) ‖ E_k(S ⊕ 2) ‖ …`, AES as
  `E`. Tweaks have variable length and messages are at least one block long.
- Security (§"Security bound"): tweakable SPRP with
  `Adv ≤ Adv^{±prp}_E(σ+2, t+σt′) + (3σ² + 2qσ + q² + 7σ + 2) / 2^{n+1}`,
  with `n = 128`, where σ is the total number of blocks queried. At
  σ = 2^48 blocks (4 PiB) the information-theoretic term is about 2^-31.
- Effect on storage: any change to a sector randomises the **whole** sector.
  A2 learns only whether a sector changed, but the scheme is still
  deterministic: rewriting identical content gives identical ciphertext.
  A3 can still replay a whole old sector. HCTR2 provides no integrity.
- Deployment: Linux fscrypt supports AES-256-HCTR2 for **filenames** and
  recommends XTS for contents (kernel fscrypt documentation, opened), and it
  states that "authenticated encryption modes are not currently supported".

### 4.3 Theca-A: authenticated sectors make wide-block unnecessary

Once Theca stores integrity metadata per sector (goal 3), the format is no
longer length-preserving. Wide-block was the best achievable **without**
metadata; with metadata, a randomised AEAD is strictly better. Per write of
logical sector `i` (4096 bytes):

```
r  ← crypto/rand, 40 bytes            (stored in sector metadata)
Nc = r[0:24]                          XChaCha20 nonce (192 bits)
Na = r[24:40]                         AES-256-CTR initial counter block (128 bits)
C  = P ⊕ XChaCha20(Kc, Nc)[0:4096] ⊕ AES-CTR(Ka, Na)[0:4096]
t  = HMAC-SHA-256(Km, "theca/v1/TA1/leaf" ‖ cid ‖ u64(i) ‖ r ‖ C)[0:24]
store C in the data area, (r, t) in the metadata area (64 bytes per sector)
```

`cid` is the container's random 16-byte identifier, held inside the encrypted
header.

Properties:

- **Encrypt-then-MAC** with independent keys: IND-CPA encryption plus a
  strongly unforgeable MAC gives IND-CCA and INT-CTXT. This is Bellare and
  Namprempre (Asiacrypt 2000), cited from memory, **not opened**.
- **Randomised**: A2 learns only *that* sector `i` was written, not whether
  its content changed. This is better than both XTS and HCTR2.
- **Not malleable**: any change to `C`, `r` or the sector position is rejected.
- **Rollback-safe nonces**: nonces are random, not counters. If A4 restores an
  old image and the owner keeps writing, a counter-based nonce would repeat and
  give a two-time pad. A random nonce does not.
- Nonce collision bound. XChaCha20 with 192-bit random nonces: q writes
  collide with probability about q²/2^193. AES-CTR with a 128-bit random
  initial block and 256 blocks per sector: two writes overlap with probability
  at most about q²·256/2^128, which is ≈ 2^-40 at q = 2^40 sector writes
  (4 PiB written). Even if the AES ranges overlap, the XChaCha20 layer still
  hides the plaintext, because the combiner only needs one layer to be sound.
- Tag length: 24 bytes (192 bits). Forgery probability per attempt is 2^-192.
  The Merkle tree (§5) hashes these tags, but collisions among keyed tags are
  not useful to an adversary without `Km`.
- Cost: 64 bytes of metadata per 4 KiB sector (1.56%), plus the tree (§5.3).

### 4.4 Adiantum

Crowley and Biggers, *Adiantum* (FSE 2019 / ToSC; read from the authors'
LaTeX source in google/adiantum, `specification/proof.tex`). HBSH is
hash–block cipher–stream cipher–hash: NH and Poly1305 hashing, XChaCha12, and
**one AES-256 call** per sector. The proof (§"Security definitions") requires
the block cipher to be an SPRP **and** the stream cipher to be secure, so
Adiantum's security is the **conjunction** of AES and XChaCha12, not the
disjunction. Adiantum exists for CPUs without AES instructions. It is not a
family-diversity construction.

### 4.5 Can HCTR2 compose with a ChaCha layer? (length-preserving profile)

For a future **Theca-L** profile (raw partitions where no metadata space is
available) we examined the options and found none that gives family diversity
without inventing something:

1. **HCTR2 ∘ Adiantum** (independent keys). This is an SPRP if either is an
   SPRP (§3.2). But both depend on AES (Adiantum needs AES as an SPRP), so a
   break of AES breaks both. No diversity.
2. **HCTR2 ⊕ a per-sector ChaCha pad** with nonce = sector index. The pad
   repeats on every rewrite of the sector. If AES fails, the outer layer is a
   reused one-time pad. That is worthless against A2.
3. **HCTR2 over a cascaded 128-bit block cipher** (AES ∘ an ARX block
   cipher). There is no standardised, well-analysed 128-bit ARX block cipher
   we would accept (Speck has a contested provenance, and Threefish's block is
   256 bits or wider and does not fit POLYVAL's GF(2^128)).

Conclusion: **Theca-L would be single-family (AES-256-HCTR2)** and documented
as weaker than Theca-A. A pure-Go HCTR2 exists (`github.com/ericlagergren/hctr2`,
BSD-3, last published 2022, 0 importers per pkg.go.dev). It would need review
against google/hctr2's test vectors and an asmgen POLYVAL kernel. Theca-L is
not in v0.1.

### 4.6 Open questions

- **Q2.1** Sector size: 4096 bytes (matches page cache and modern drives) is
  proposed. Larger logical sectors (e.g. 16 KiB) would cut metadata to 0.4%
  but increase read amplification.
- **Q2.2** Is Theca-L wanted at all? It exists mainly for in-place conversion
  of a full partition. **Decided (D7):** not in v0.1.

---

## 5. Goal 3 — integrity and rollback

### 5.1 Prior art

- **dm-integrity** (kernel documentation, opened). Provides per-sector tags
  with an optional HMAC. Its modes are journaled J ("data and integrity tags
  are written to the journal and atomicity is guaranteed"), direct D (data
  and tag may disagree after a crash), and bitmap B (faster; regions are
  recalculated after a crash, "less reliable"). Cost: "the journaled mode
  degrades write throughput twice because the data have to be written
  twice". The document does **not** claim replay or rollback protection:
  per-sector tags with no freshness accept an old (sector, tag) pair.
- **Broz, Patocka, Matyas**, *Practical cryptographic data integrity
  protection with full disk encryption* (IFIP SEC 2018, arXiv 1807.00309,
  abstract opened). Algorithm-agnostic per-sector metadata in software, merged
  into Linux 4.12. This is the design dm-crypt + dm-integrity implements.
- **dm-verity** builds a read-only hash tree; it was **not opened** for this
  document. Theca needs a read–write tree, which dm-verity does not provide.

### 5.2 Design

- **Leaves**: the 24-byte tags `t_i` from §4.3, which bind (cid, i, r, C). The
  sector index in the tag blocks sector swaps, and the cid blocks splicing
  sectors in from another container.
- **Level 1 is the metadata block itself.** One 4 KiB metadata block holds
  the `(r, t)` pairs of 64 consecutive sectors. Its tree value is
  `N1 = HMAC-SHA-256(Km, "theca/v1/TA1/n1" ‖ metadata block)`. Tags are stored
  once, in the metadata area, not again in tree nodes.
- **Levels ≥ 2**: 128-ary. A 4 KiB node holds 128 × 32-byte child values;
  its value is `HMAC-SHA-256(Km, "theca/v1/TA1/n" ‖ u8(level) ‖ children)`.
  Position is fixed by the path (the child slot), and the leaf tags already
  bind the sector index. No node index enters the hash, so defaults can be
  constants.
- **Sparse defaults** (review finding R5). A metadata block that was never
  written has the constant value `D1 = HMAC(Km, "theca/v1/TA1/empty")`, and
  `D(l+1)` is the node value of 128 copies of `D(l)`. A parent records
  `D(l)` for untouched children. A reader that reaches `D1` returns zeros for
  those 64 sectors without reading the metadata block, which still holds
  random filler. Creation computes about `depth` HMACs, not 2^28, and needs no
  encryption pass, only the random fill required for indistinguishability (§9).
- **Root**: stored in the encrypted header body together with the epoch `e`
  (a 64-bit counter of commits). The header body is authenticated (§9), so
  (root, e) is authenticated.
- **Freshness inside one container**: any old (sector, tag) pair fails against
  the current root. This closes the replay gap that dm-integrity leaves.
- **Freshness of the whole container (A4)**: no data-only scheme can detect
  the replacement of everything by a genuine older copy. Detection needs state
  outside the container: a monotonic counter (§5.4).

### 5.3 Cost of random-access updates

For 1 TiB of 4 KiB sectors: 2^28 sectors, 2^22 metadata blocks (16 GiB
including the nonces, 1.56%). Above level 1 there are ⌈22/7⌉ = 4 levels of
128-ary nodes: 2^15 nodes (128 MiB), 2^8 (1 MiB), 2 nodes, and the root.

- **Read**: one data read plus its metadata block (shared by 64 neighbouring
  sectors). The block is checked against its level-2 parent. Levels ≥ 2
  (≈ 129 MiB at 1 TiB) can be cached in RAM, so the steady state is one
  metadata-block read per cache miss.
- **Write**: data, the whole metadata block (a 64-byte update rewrites the
  4 KiB block that holds 63 neighbours' tags), and the dirty path. Dirty
  blocks and nodes are coalesced in RAM until the next commit. The root and
  epoch are written once per commit, not per write.
- **Crash consistency**: data, metadata blocks and tree nodes must move
  atomically from one committed root to the next. v0.1 uses a **write-ahead
  journal** (dm-integrity J semantics) covering **all three** kinds of block,
  so writes cost **2×** plus metadata. A log-structured layout (write out of
  place, then switch roots) would remove the 2× and aligns with Palimpsest
  (§8); it is the main v0.3 item.
- **Journal records must not be replayable** (review finding R1). Every
  journal record is sealed with Theca-A, and its MAC input includes the
  target epoch `e+1`, a record sequence number and the destination (area,
  block index). A transaction ends with a commit record whose MAC covers the
  hash of all its records and the **new root**. Recovery replays a transaction
  only if its epoch equals the header epoch + 1, its sequence is complete, and
  the root recomputed after applying it equals the root in the commit record.
  Anything else is discarded. An older genuine transaction copied into the
  journal fails the epoch check.
- Commit policy: on `fsync`, on unmount, and at most every 30 s while dirty.
  Commits advance the epoch `e`, **not** the hardware counter (§5.4).

### 5.4 Monotonic counter: where it can live

| Platform | Mechanism | From pure Go? | Notes |
|---|---|---|---|
| Linux, Windows with TPM 2.0 | NV index of type `TPM_NT_COUNTER`, incremented with `TPM2_NV_Increment` (TCG TPM 2.0 Library Part 3 rev 1.83, §31.8, opened) | Yes: go-tpm2/tpm2 has `NVDefineSpace/NVRead/NVWrite` (`nv.go`); **`NVIncrement` is missing and must be added there** | Part 3, p. 376: a newly defined counter starts "greater than any count value for any NV counter on the TPM since the time of TPM manufacture", so undefine-and-redefine cannot reset a **counter**, but an attacker could redefine the handle as an ordinary index (see the protocol below). `TPMA_NV_ORDERLY` is **not** used: after a non-orderly shutdown it advances the counter by `MAX_ORDERLY_COUNT` (§31.8.1, note 2). |
| macOS | Secure Enclave counter lockboxes exist (Apple Platform Security guide, opened) but serve passcode attempts | **No third-party interface found** in the guide. That is not proof of absence; the developer documentation could not be read (JS-only page). | Remote witness, or none |
| Any | Remote witness: a service that signs `(cid, e)` and refuses to sign a lower `e` | Yes | Availability dependency. Design later (C2SP tlog-witness is a candidate, **not opened**). |
| Any, experimental | FIDO2 authenticator signature counter | go-authn/fido parses `signCount` | Fragile: counters may be global per key, and failed unlocks advance them. Research only. |

Protocol (TPM case), revised after review finding R2. The counter advances
**once per mount session**, not per commit, so NV wear is one write per mount
and `TPM_RC_NV_RATE` is not a concern.

- **Creation**: define an NV index with `TPM_NT_COUNTER`,
  `TPMA_NV_POLICY_DELETE` (so the owner hierarchy alone cannot delete it) and
  an authorisation policy for writing. Increment it once so that it is written,
  then read its value `c0`. That value is large, because the TPM starts new
  counters above every earlier count. The authenticated header body records
  the index handle, its **NV Name** (which covers type, attributes and policy)
  and the bound value `b = c0`. The epoch `e` is separate and starts at 0.
- **Mount**: `NV_ReadPublic` must return exactly the recorded Name; otherwise
  refuse. A redefined ordinary index has a different Name. Read the counter
  `c`. Accept iff `b == c` or `b == c+1`. Then write the header with
  `b = c+1`, flush, and `NV_Increment`. The `b == c+1` case only arises from
  a crash between that header write and the increment, and it resolves by
  incrementing.
- An image from any **earlier session** has `b ≤ c-1` and is refused. The
  same refusal appears if the owner restores a backup on purpose, so the CLI
  offers an explicit, loud `recover --accept-rollback` that rebinds the
  header to the current counter. It never accepts a rollback silently.

Threats covered: A3 fully. A4 across sessions where a counter exists. Within
the **current** session, a copy taken mid-session (e.g. by a sync client) can
be substituted at the next mount; that window is the last session, stated in
the CLI output at mount, as is the absence of any counter.

**Q3.1** Which write policy for the index: a policy bound to a TPM-resident
Theca key, or `authValue` from the unlock (the latter allows increments only
after unlock)? **Q3.2** What should happen on a platform without a counter:
refuse, warn, or record "rollback-unprotected" in the header?

---

## 6. Goal 4 — key derivation and access

### 6.1 Argon2id (RFC 9106, opened)

- RFC 9106 §4 recommends: FIRST option Argon2id **t=1, p=4, m=2 GiB**; SECOND
  (memory-constrained) **t=3, p=4, m=64 MiB**; salt 128 bits; tag 256 bits.
  §4 steps 3–11 give a tuning procedure (fix p, choose m, then the largest t
  that fits the time budget). §7.4 says the t=1, 2 GiB option "is secure
  against side-channel attacks and maximizes adversarial costs on dedicated
  brute-force hardware". §7.2 gives the best known trade-off attack on 1-pass
  Argon2id as a factor of about 2.1.
- Theca uses a **fixed parameter table compiled into the binary**: profile 0 =
  RFC FIRST, profile 1 = RFC SECOND, profile 2 = "paranoid" (t=3, m=4 GiB).
  The profile is **never read from the container**: a header has no
  plaintext fields (§9). This also removes a resource-exhaustion vector,
  because a hostile container cannot request a 4 TiB allocation. The cost is
  that the unlocking side must know the profile. **Decided (D2):** the user
  names it with a hint (like VeraCrypt's PIM), and profile 0 is the default.
  There is no ladder.
- Salt: 32 bytes at a fixed offset, random. One salt is shared by all password
  slots, so unlocking costs **one** Argon2id evaluation followed by cheap trial
  decryptions of each slot (§9.2).
- Implementation: `golang.org/x/crypto/argon2` (`IDKey`). In module v0.59.0
  the BlaMka kernel has amd64 (SSE4.1) and loong64 assembly and **no arm64
  assembly**, so Apple Silicon runs generic Go. Expect a gap against the
  reference C on arm64 (§11).

### 6.2 Access factors and the 2-of-3 policy

Shamir, *How to share a secret* (CACM 22(11), 1979, opened). In a (k, n)
threshold scheme, k pieces make D "easily computable", and k−1 pieces leave D
"completely undetermined (in the sense that all its possible values are
equally likely)".

Factors:

- **F1 password**: KEK₁ = HKDF(Argon2id(password, salt), info=`theca/v1/TA1/slot/pw`).
- **F2 hardware-bound**: KEK₂ released by a TPM (sealed object), a Secure
  Enclave key (ECDH), or a FIDO2 security key (`hmac-secret`). See §6.3.
- **F3 printed recovery code**: 160 random bits printed as 32 base32
  characters plus a check symbol. KEK₃ = HKDF(code, info=`theca/v1/TA1/slot/rc`).
  No Argon2 is needed because the code has full entropy.

Every slot is sealed with **TA1 itself**: each 32-byte KEK is expanded by
HKDF into three keys for XChaCha20, AES-256-CTR and HMAC. Wrapping therefore
keeps both cipher families (review finding R4).

Two constructions were considered. **Decided (D3): (b), pairwise slots.**
They are **not** equivalent in the form first drafted (review finding R3):

- **(a) Shamir**: MS (96 bytes) is split 2-of-3 bytewise over GF(2^8) with
  fixed x-coordinates 1, 2, 3, and share j is encrypted under KEK_j. **A share
  slot MUST carry no per-slot tag.** With a tag, the password slot alone would
  confirm a password guess offline, without F2, and the 2-of-3 policy would
  give no protection against guessing. Share slots are therefore encrypted
  with the TA1 keystream only. The single verifier is the header body,
  opened with the MS reconstructed from two candidate shares (key-committing,
  §9.3). Unlocking decrypts every slot under each available KEK and tries the
  candidate pairs against the header. That is at most 16 × 16 Lagrange
  interpolations and header MAC checks, which is negligible next to Argon2id.
  The construction generalises to k-of-n, and any single share is
  information-theoretically useless. GF(2^8) arithmetic MUST be constant-time
  (no log/exp tables indexed by secrets).
- **(b) Pairwise slots**: three slots wrap MS under HKDF(KEK_a ‖ KEK_b) for
  each pair {a, b}. Each slot can carry a normal TA1 tag, because checking it
  already needs two factors. There is no new arithmetic, but it does not
  generalise beyond small n. **Chosen for v0.1** because it is the simpler
  construction to get right.

Honest consequences, to be printed in the documentation:

- With 2-of-3, **password + recovery code** suffice. Anyone holding the
  printed code faces only the password's Argon2id strength.
- If the device holding F2 is stolen **and** F2 releases its secret without
  user verification, then F2 + an offline guess of F1 is the attack.
  Mitigation: release F2 only with user verification. For a TPM this means
  an `authValue` under TPM dictionary-attack lockout: a **separate PIN**, or
  a value derived from the Argon2id output under its own HKDF label. It is
  **never the raw password**, so a TPM-side leak or a sniffed bus does not
  hand the password to the attacker. For FIDO2 it means `uv=true`; for the
  Secure Enclave, an access control requiring user presence.
- Rotation of any factor needs MS, i.e. two factors present.

### 6.3 What pure Go can reach

| Factor | Path | State in our orgs | Gaps |
|---|---|---|---|
| TPM 2.0 (Linux `/dev/tpmrm0`, Windows TBS) | Seal a 32-byte KEK₂ under the SRK with a policy (authValue, optional PCRs) | go-tpm2/tpm2: `seal.go`, `nv.go`, `import.go`; transports `devtpm`, `crb`, `tis` | `NVIncrement` (§5.4); Windows TBS transport not seen in the repo list |
| Secure Enclave (macOS) | P-256 key in the SE; KEK₂ = HKDF(ECDH(SE key, stored ephemeral public key)) via Security.framework through purego | go-macos/keychain proves purego calls into Security.framework (Keychain items, `SecAccessControl`) | SE key creation and `SecKeyCopyKeyExchangeResult` unbound. Whether persistent SE keys need a signed binary with a keychain-access-group entitlement is **unverified** (Apple's developer page could not be read). Spike before committing. |
| FIDO2 security key (any OS) | CTAP2 `hmac-secret`: KEK₂ = HMAC from the authenticator over a stored salt | go-authn/fido: CTAPHID, `GetInfo`, `MakeCredential`, `GetAssertion`, ClientPIN protocols 1 and 2 (tested on a YubiKey 5.7.4) | `hmac-secret` is not listed in the README; it must be added in go-authn/fido. The CTAP 2.1 `hmac-secret` section was **not opened**. |

---

## 7. Goal 5 — post-quantum recipients

- **Primitive**: X-Wing, draft-connolly-cfrg-xwing-kem-11 (opened). The
  combiner (§5.3) is `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`. Sizes
  (§5.1): public key 1216 B, ciphertext 1120 B, private key 32 B. Claim (§6):
  IND-CCA if SHA3 is secure and **either** X25519 or ML-KEM-768 is secure
  (formal statement in the ROM, citing a separate proof). Status: individual
  submission to the Independent Submission stream, **not** a CFRG document.
- **Go**: Go 1.27.4 (the toolchain in use) ships `crypto/hpke` with
  `MLKEM768X25519()`, whose documentation reads "MLKEM768-X25519 (a.k.a.
  X-Wing) from draft-ietf-hpke-pq". draft-ietf-hpke-pq-05 (opened) assigns
  KEM id 0x647a. `crypto/mlkem` (FIPS 203) and `crypto/hkdf` are present.
  Nothing has to be implemented by us.
- **Use**: HPKE Base mode, KDF HKDF-SHA256, AEAD **ExportOnly**. The sender
  exports a 32-byte secret with context `theca/v1/TA1/recipient`, expands it
  into three keys, and seals MS (or a share) with **TA1**. Sealing with HPKE's
  ChaCha20Poly1305 would make one cipher family the single guard of MS and
  undo the cascade (review finding R4).
- **Threat model**: A6 for key wrapping. Bulk data is symmetric (256-bit
  keys), where Grover gives at most a square-root speed-up.
- **Conflict with §9 (no magic)**: an X-Wing ciphertext is **not** uniform. An
  honestly generated X25519 public key always has bit 255 clear and never
  lies on the twist (every 32-byte string *decodes*, but the distribution is
  not uniform), and ML-KEM ciphertexts are compressed polynomial
  coefficients. Making slots uniform needs:
  - **Kemeleon** (draft-irtf-cfrg-kemeleon-02, CFRG research-group document,
    opened). ML-KEM-768 ciphertext encoded to 1536 B (base variant, never
    fails) or 1252 B (rejection variant, ~23% retry). Security rests on
    module-LWE. The encoding randomness must stay secret (§6.2), and big-integer
    arithmetic is a timing concern (§6.3).
  - **Elligator 2** for the X25519 ephemeral key. Bernstein, Hamburg, Krasnova,
    Lange, CCS 2013; **not opened** (the site failed to load).
  - Control over the encapsulation randomness, to retry until the ephemeral
    point is representable. Go's `crypto/hpke` does not expose it, so this
    means our own HPKE-compatible encapsulation over `crypto/mlkem` and
    `crypto/ecdh`.
- **Cost**: ~2.6 KiB per uniform recipient slot. Encapsulation cost is
  negligible next to Argon2id.
- **Decided (D4)**: recipients arrive in v0.2, with uniform encoding. The
  header is never distinguishable from random.

---

## 8. Goal 6 — "Palimpsest": deniability against multiple snapshots

### 8.1 Sources

- **HIVE**: Blass, Mayberry, Noubir, Onarlioglu, *Toward robust hidden volumes
  using write-only oblivious RAM*, CCS 2014 (opened). Gives the first formal
  definitions for hidden-volume encryption and shows TrueCrypt-style hidden
  volumes fail against multi-snapshot adversaries (comparing snapshots shows
  "free" blocks changing). Introduces a write-only ORAM with O(1)
  communication complexity. Measured (§6, bonnie++, Samsung 840 EVO SSD):
  sequential I/O slower "by a factor of ≈ 200", filesystem operations 50–60×
  slower, throughput "≈ 1 MByte/s".
- **DataLair**: Chakraborti, Chen, Sion, PoPETs 2017 (arXiv 1706.10276,
  abstract opened). A new write-only ORAM that improves the previous best by a
  factor of O(log N). Reported as "two orders of magnitude faster for public
  data accesses" and 5× faster for hidden data than existing approaches.
- **PD-DM**: Chen, Chakraborti, Sion, PoPETs 2019(1) 153–171 (opened: abstract
  and introduction). Argues the access randomisation behind earlier systems'
  cost is unnecessary and replaces it with a canonical form that makes most
  writes sequential. Reports 10–100× more throughput than prior work and is
  "within reach" of dm-crypt for random I/O.

### 8.2 What it would take in Theca

- All physical writes, public and hidden, go through a write-only ORAM or a
  PD-DM-style canonical log. Every public write also rewrites some "free"
  blocks with fresh ciphertext, which carries hidden data or is indistinguishable
  filler.
- The integrity tree, the journal and the epoch of the **hidden** volume must
  themselves be hidden inside the same mechanism. A public tree that covers
  hidden blocks would reveal them.
- Rollback counters, TPM NV indices and recipient slots are visible artefacts.
  A hidden volume cannot use a visible counter without revealing itself.
- **The environment defeats it easily**: a container *file* on APFS, ZFS or
  btrfs (copy-on-write, snapshots, Time Machine) or on an SSD (FTL remapping)
  hands A2 extra snapshots and stale blocks that Theca cannot control.
  Deniability claims would have to be limited to raw block devices with TRIM
  off, which is a narrow and fragile envelope.
- The hidden volume is only deniable if the public volume is actually used.

### 8.3 Verdict

Not feasible for v0.1, and not honestly claimable for a container file on a
modern host filesystem. Proposed path: (1) v0.3's log-structured layout
(§5.3) adopts PD-DM's canonical-form idea for performance alone; (2)
Palimpsest becomes a v1.x research track with its own threat-model document,
only for raw devices, with costs measured against PD-DM's published numbers.
**Decided (D5)**: it stays on the roadmap, for raw devices only, with no date.

What v0.1 does give: **single-snapshot** indistinguishability of the
container from random data, and of the number of used keyslots (§9).

---

## 9. Goal 7 — header and metadata

### 9.1 No magic

Every byte of a Theca container at rest is either ciphertext or random
filler: no magic, no version field, no plaintext parameters. Unused keyslots,
unused metadata and the data area are filled at creation from a
ChaCha20-based CSPRNG seeded from `crypto/rand`. Unwritten sectors need no
encryption pass because they are represented in the tree (§5.2). A whole
container is indistinguishable from a random file of the same length to A1,
**unless** recipient slots are present before Kemeleon/Elligator (§7). The
remaining leaks are the size (rounded to 1 MiB) and the file name, which the
documentation must say.

### 9.2 Layout sketch (subject to change)

```
offset 0       salt (32 B, random)
offset 32      16 keyslots × 2048 B           (unused slots: random)
offset 32800   header body copy A (8 KiB, sealed with TA1 under Kc, Ka, Km,
                                   label theca/v1/TA1/header, 32-byte tag)
               header body copy B (8 KiB)      (A/B alternate by epoch)
               journal area
               metadata area (64 B per sector: r ‖ t; these blocks are tree level 1)
               tree area (levels ≥ 2, 4 KiB nodes)
               data area
               random tail to the next MiB
```

Unlock: one Argon2id (shared salt), then trial-open **all** 16 slots and
**both** header copies every time, and keep the valid copy with the higher
epoch. The work done never depends on which slot matched, so timing does not
reveal the slot (review finding R8). Cost beyond Argon2id: 16 small slot
operations, the share combinations of §6.2 when 2-of-3 is used, and the header
verifications.

### 9.3 Key commitment and domain separation

Trial decryption over several slots and candidate keys is the setting of
**partitioning oracle attacks** (Len, Grubbs, Ristenpart, USENIX Security 2021,
ePrint 2020/1491, opened). Non-committing AEADs such as AES-GCM and
ChaCha20-Poly1305 let an attacker build one ciphertext valid under many keys
and test many passwords per query. A stored container has no online
decryption oracle, so the direct attack does not apply to v0.1. It would
apply to a future unlock *service* (remote witness, network unlock), and
commitment is cheap, so we keep it.

Theca's header encryption is EtM with a full-length (32-byte) HMAC-SHA-256
tag. The claim is narrow (review finding R6). HMAC has **equivalent keys**:
a key K and K ‖ 0x00, or a key longer than the block and its hash, give the
same tag. Commitment therefore holds only because every MAC key in Theca is
**exactly 32 bytes**, produced by `crypto/rand` or HKDF-SHA-256. For such
keys, two keys accepting one ciphertext would need a collision in
SHA-256-based HMAC outputs, so the scheme is key-committing under SHA-256
collision resistance. Share slots in construction (a) carry no tag at all
(§6.2), and their only verifier is this committing header.

Every HKDF `info` and HMAC label starts with `theca/v1/<suite>/`. A key or tag
from one version, suite or purpose is never valid in another.

### 9.4 Versioning and agility without downgrade

- There is no negotiation (storage has no live peer). A **suite** is a complete
  named profile, as with HPKE or Noise suites, not a menu of independent
  choices. v0.1 has exactly one suite: `TA1 = XChaCha20 ⊕ AES-256-CTR, HMAC-SHA-256, Argon2id, HKDF-SHA-256`.
- The version and suite are bound into every key derivation (§9.3) and stored
  inside the authenticated header body. An attacker cannot relabel a container
  without the keys.
- The reader tries (version, suite, Argon2 profile) tuples newest-first from
  its compiled-in table. A reader also has a **minimum suite** floor. A
  retired suite is refused, not "supported with a warning". Upgrading
  re-encrypts the header and slots and, if the bulk suite changes, the data
  (online, sector by sector, tracked in the header).
- "Downgrade" in storage means presenting an *older genuine* container. That
  is rollback (A4), handled by §5.4, not by format logic.

---

## 10. Format invariants (normative sketch)

1. A reader MUST NOT derive any allocation size from container bytes before
   authentication. Sizes come from the compiled-in table or from the
   authenticated header body, and the latter MUST be range-checked (sector
   count ≤ 2^40, journal ≤ 1 GiB, and so on).
2. A reader MUST verify a sector's tag and its tree path before returning
   plaintext.
3. A writer MUST draw `r` from `crypto/rand` for every sector write,
   including rewrites of identical data.
4. Integers are little-endian, fixed width, and computed in `uint64` (32-bit
   targets included).
5. Header body copies alternate. A writer MUST NOT overwrite the copy holding
   the current epoch.

---

## 11. Performance targets and references

### 11.1 References (single core, interleaved rounds, per the fleet rule)

| Primitive | Theca implementation | Reference to beat or match |
|---|---|---|
| XChaCha20 keystream | `golang.org/x/crypto/chacha20` | libsodium `crypto_stream_xchacha20`; OpenSSL `speed -evp chacha20` |
| AES-256-CTR | Go `crypto/aes` + `crypto/cipher` CTR | OpenSSL `speed -evp aes-256-ctr` |
| HMAC-SHA-256 | Go `crypto/hmac` + `crypto/sha256` | OpenSSL `speed -hmac sha256`; libsodium `crypto_auth_hmacsha256` |
| Argon2id (t=1, p=4, 2 GiB; one thread) | `golang.org/x/crypto/argon2` | P-H-C `phc-winner-argon2` reference CLI, threads=1 |
| Composite Theca-A per 4 KiB sector | ours | Sum of the three primitives' costs + ≤ 5%; and VeraCrypt AES-Twofish-Serpent XTS (go-fde/veracrypt) as the competitor |
| (later) HCTR2 | to port | google/hctr2 benchmarks; Linux `hctr2` |

### 11.2 Gaps known from source (x/crypto v0.59.0 module listing)

- `chacha20`: assembly for arm64, ppc64x, s390x and loong64; **none for
  amd64**, which runs generic Go. Expect a gap against libsodium's AVX2 code.
- `argon2`: BlaMka assembly for amd64 and loong64; **none for arm64**.
- `internal/poly1305`: no arm64 assembly. It is used only by HPKE's
  ChaCha20Poly1305 on small payloads, so it is irrelevant to throughput.
- Per the fleet rule, missing kernels go to the lowest shared library: an
  asmgen-generated amd64 ChaCha20 and an arm64 BlaMka belong in a go-encryptions
  package (or upstream to x/crypto), not in Theca. The AES-CTR and SHA-256
  paths in Go's standard library use hardware instructions on amd64 and arm64;
  measure them before assuming anything.

### 11.3 Targets

- Each primitive: at parity (within noise) with the best reference on the
  same core. Slower is an open defect.
- Composite read and write, 4 KiB random, cache warm: ≥ 0.8 GB/s per core on
  Apple M-series, an *estimate* from ChaCha20 ≈ 2 GB/s, HMAC-SHA-256 ≈ 2 GB/s
  and AES-CTR ≫ both. Writes are halved by the journal until v0.3.
- Unlock: ≤ 1.5 s at Argon2id profile 0 on the reference machine.
- **Not measured yet**: the 1-minute load on the design host was 39.5 at
  15:22 CET on 2026-11-15, far above the ~8 ceiling for meaningful timings.
  The first implementation PR carries the table.

---

## 12. What already exists (verified 2026-11-15)

| Need | Where | Evidence |
|---|---|---|
| AES (hardware), CTR, HMAC, SHA-256, SHA-3, HKDF, ML-KEM, HPKE with X-Wing | Go 1.27.4 standard library | `go doc crypto/mlkem`, `crypto/hkdf`, `crypto/hpke` (`MLKEM768X25519`), `go list std` |
| ChaCha20, XChaCha20, Argon2id | `golang.org/x/crypto` (not std; std only vendors chacha20 internally) | module cache listing v0.59.0 |
| XTS (with amd64/arm64 assembly), Serpent, Twofish, Whirlpool, CBC, Camellia, Kuznyechik | go-encryptions | `gh repo list go-encryptions`. There is **no `go-encryptions/aes` repository**; AES comes from std. |
| VeraCrypt, ZED!, LUKS, BitLocker, APFS readers | go-fde | `gh repo list go-fde` |
| TPM 2.0 seal / NV / import, transports | go-tpm2 | `tpm2` repo file list (`nv.go` lacks NV_Increment) |
| FIDO2 CTAP2 client | go-authn/fido | README (no `hmac-secret` yet) |
| Keychain via purego | go-macos/keychain | README |
| Code generation for SIMD kernels | go-asmgen, go-simd | local clone `go-asmgen-asmgen` |
| HCTR2, Adiantum, Kemeleon, Elligator 2, Shamir | **none in our orgs** | `fleetfind chacha / argon / kem / hctr / adiantum / shamir / poly1305` over 2253 repositories: no match (names and descriptions only, not code) |

---

## 13. Security engineering requirements

- **Fuzzing** (corpus committed): slot trial-open, header body parse, tree
  node parse, journal replay, recovery-code parser. Every parser runs only
  after authentication, but fuzzing still covers the pre-authentication trial
  path and the post-authentication range checks.
- **Bounds**: §10.1. A 32-bit build is tested in CI. Container size math stays
  in `uint64`.
- **Constant time**: Shamir GF(2^8), tag comparison (`hmac.Equal`), recovery
  code checksum.
- **Secrets in memory**: Go's GC may copy. We keep keys in fixed slices,
  zeroise on unmount, and document the limit. Whether newer Go releases offer
  a supported secret-erasure facility is to be checked, not assumed.
- **Failure modes**: wrong password and corrupted container produce the
  same error up to the slot stage (no oracle). After unlock, a tag failure is
  an I/O error naming the sector, never silently zero data.
- `govulncheck` in CI. Bomb tests (huge sector counts in a forged-but-keyed
  header) assert a **refusal** under `GOMEMLIMIT` and `ulimit -v`.

---

## 14. Phased plan

**v0.1 — "it holds data correctly"**
- Suite TA1, Theca-A sectors (4 KiB), 128-ary tree, write-ahead journal, A/B
  header, no-magic layout with 16 slots.
- Access: password slots (Argon2id profiles 0/1/2, selected by a hint) and a
  recovery-code slot, as 1-of-n; plus 2-of-3 through pairwise slots with
  F2 = **TPM 2.0** (Linux first).
- Rollback: TPM NV counter where present (adds `NVIncrement` to go-tpm2/tpm2);
  otherwise mount reports "rollback-unprotected".
- Library API (`Create/Open/ReadAt/WriteAt/Sync/Close`) plus a cobra CLI
  (`create`, `addslot`, `verify`, and `get`/`put` of byte ranges for
  testing). No mounting in v0.1 (D6).
- Benchmarks of §11 against OpenSSL, libsodium and the Argon2 reference;
  fuzzers; README, landing and docs updates.

**v0.2** — mounting through FUSE/NBD (D6); FIDO2 `hmac-secret` factor
(YubiKey Bio, see the forthcoming `docs/HARDWARE-KEYS.md`) and the Secure
Enclave factor; PQ recipients with Kemeleon + Elligator 2, keeping the header
uniform (D4); remote witness; asmgen kernels (amd64 ChaCha20, arm64 BlaMka)
in go-encryptions.

**v0.3** — log-structured layout (no 2× journal), online re-encryption and
MS rotation (true revocation, §2). No HCTR2 profile is planned (D7).

**Roadmap, no date** — Palimpsest, raw devices only (D5); MAC combiner (Q1.1).

---

## 15. Decisions

Decided 2026-11-15 by the user (author: user).

- **D1** The cascade is **on by default**. v0.1 has one suite, TA1.
- **D2** The Argon2id profile is selected by a **user-supplied hint**
  (PIM-like). There is no ladder: an unlock costs exactly one Argon2id
  evaluation. Without a hint, profile 0 is used.
- **D3** 2-of-3 uses **pairwise slots**, not Shamir. One planned hardware
  factor is a **FIDO2 `hmac-secret`** authenticator (YubiKey Bio
  Multi-protocol, fingerprint verification). The details are in
  `docs/HARDWARE-KEYS.md`, forthcoming in a separate pull request.
- **D4** Post-quantum recipients come in **v0.2**, with uniform encoding
  (Kemeleon + Elligator 2), so the header stays indistinguishable from random.
- **D5** Palimpsest **stays on the roadmap**, for raw devices only, with no
  date.
- **D6** v0.1 is **library + CLI only**. Mounting (FUSE/NBD) comes in v0.2.
- **D7** There is **no HCTR2 single-family profile** in v0.1.

---

## 16. Bibliography

### Opened for this document

1. U. Maurer, J. Massey. *Cascade ciphers: the importance of being first.*
   J. Cryptology 6(1):55–61, 1993. <https://doi.org/10.1007/BF02620231>.
   **Abstract and first page only** (full text paywalled).
2. P. Crowley, N. Huckleberry, E. Biggers. *Length-preserving encryption with
   HCTR2.* ePrint 2021/1441, <https://eprint.iacr.org/2021/1441>. Read: the
   abstract and the LaTeX sources `specification.tex` and `security.tex` at
   <https://github.com/google/hctr2/tree/main/paper>.
3. P. Crowley, E. Biggers. *Adiantum: length-preserving encryption for
   entry-level processors.* FSE 2019, ePrint 2018/720,
   <https://eprint.iacr.org/2018/720>. Read: the abstract and `proof.tex` at
   <https://github.com/google/adiantum/tree/master/specification>.
4. NIST SP 800-38E, *The XTS-AES mode for confidentiality on storage
   devices*, 2010 (abstract and contents),
   <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf>.
5. Linux kernel, *Filesystem-level encryption (fscrypt)*,
   <https://docs.kernel.org/filesystems/fscrypt.html>.
6. Linux kernel, *dm-integrity*,
   <https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html>.
7. M. Broz, M. Patocka, V. Matyas. *Practical cryptographic data integrity
   protection with full disk encryption.* IFIP SEC 2018,
   <https://arxiv.org/abs/1807.00309> (abstract).
8. A. Biryukov et al. RFC 9106, *Argon2 memory-hard function*, §§1, 3.4.1.3,
   4, 7.2–7.4, <https://www.rfc-editor.org/rfc/rfc9106.html>.
9. A. Shamir. *How to share a secret.* CACM 22(11):612–613, 1979 (first page),
   <https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf>.
10. TCG, *TPM 2.0 Library Part 3: Commands*, rev 1.83, §31.8 and p. 376,
    <https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf>.
11. Apple, *Apple Platform Security*, "Secure Enclave",
    <https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web>.
12. D. Connolly et al. *X-Wing.* draft-connolly-cfrg-xwing-kem-11,
    <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>.
13. *Post-quantum and hybrid KEMs for HPKE.* draft-ietf-hpke-pq-05 (first
    100 k characters), <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>.
14. *Kemeleon encodings.* draft-irtf-cfrg-kemeleon-02,
    <https://datatracker.ietf.org/doc/draft-irtf-cfrg-kemeleon/>.
15. J. Len, P. Grubbs, T. Ristenpart. *Partitioning oracle attacks.* USENIX
    Security 2021, <https://eprint.iacr.org/2020/1491> (abstract).
16. E.-O. Blass, T. Mayberry, G. Noubir, K. Onarlioglu. *Toward robust hidden
    volumes using write-only oblivious RAM.* CCS 2014 (full text),
    <https://onarlioglu.com/publications/ccs2014hive.pdf>.
17. A. Chakraborti, C. Chen, R. Sion. *DataLair.* PoPETs 2017,
    <https://arxiv.org/abs/1706.10276> (abstract).
18. C. Chen, A. Chakraborti, R. Sion. *PD-DM.* PoPETs 2019(1):153–171
    (abstract and introduction),
    <https://www.petsymposium.org/popets/2019/popets-2019-0009.pdf>.
19. VeraCrypt documentation, *Cascades*,
    <https://veracrypt.io/en/Cascades.html>.
20. Go 1.27.4 package documentation: `crypto/mlkem`, `crypto/hkdf`,
    `crypto/hpke`, `crypto/sha3` (read with `go doc`),
    <https://pkg.go.dev/crypto/hpke>.

### Cited but NOT opened (read before the relevant phase)

- IEEE Std 1619-2007 (XTS), paywalled.
- M. Bellare, C. Namprempre, *Authenticated encryption: relations among
  notions and analysis of the generic composition paradigm*, Asiacrypt 2000
  (the fetch failed on a certificate error).
- M. Bellare, *New proofs for NMAC and HMAC*, CRYPTO 2006 (same).
- D. Bernstein, M. Hamburg, A. Krasnova, T. Lange, *Elligator*, CCS 2013.
- RFC 5869 (HKDF), RFC 9180 (HPKE), FIPS 203 (ML-KEM): relied on through
  Go's implementations; not reread here.
- FIDO Alliance CTAP 2.1, `hmac-secret` extension.
- Apple developer documentation on Secure Enclave keys (JS-only page, not
  readable).
- dm-verity documentation; C2SP tlog-witness.
- S. Even, O. Goldreich, *On the power of cascade ciphers*, 1985; P. Gaži,
  U. Maurer, *Cascade encryption revisited*, Asiacrypt 2009 (403).

---

## 17. Name

"Theca" (Latin *thēca*, from Greek θήκη: case, sheath, a box for keeping
things). Collision check, 2026-11-15:

- GitHub (`gh search repos theca`, first 30 results): `rolandshoemaker/theca`,
  a Rust note-taking CLI (358 stars); `streambinder/theca`, a Solus package repository. No
  encryption or storage tool.
- crates.io: `theca` (the same note-taking tool). Storage-adjacent crates with
  the suffix: `apotheca`, `metatheca`, `syntheca`. None encrypts.
- PyPI: `theca` 3.0.5, "Python library to run your own private CA". This is
  **crypto-adjacent**: a PKI tool, not storage encryption.
- npm: `theca` does not exist (404).
- pkg.go.dev: no `theca` module; only `OxytocinGroup/theca-backend` (an API
  command).
- Trademarks: WIPO Global Brand Database **NOT READ** (CAPTCHA); EUIPO
  **NOT READ**. This is not an absence.

---

## 18. Review log

An independent review of the first draft (2026-11-15) looked at
cryptographic soundness and composition. It was given the document, not the
author's conclusions. Its findings and where they were applied:

| # | Severity | Finding | Applied in |
|---|---|---|---|
| R1 | critical | Journal transactions could be replayed to roll sectors back | §5.3: epoch, sequence and destination in each record; a commit record MACs the transaction and the new root |
| R2 | critical | TPM counter protocol: an ORDERLY jump locks the container; per-commit increments wear NV; the index could be redefined as an ordinary one | §5.4: no ORDERLY, one increment per mount, NV Name pinned, `POLICY_DELETE`, bound value starts at the counter's value |
| R3 | major | A tagged password share allows offline guessing without F2; (a) and (b) were not equivalent | §6.2: untagged shares with the header as the only verifier; pairwise slots recommended |
| R4 | major | Slots and recipients were wrapped with a single cipher family | §2, §6.2, §7: TA1 everywhere; HPKE export-only |
| R5 | major | Tree undefined for unwritten sectors; tags stored twice | §5.2: metadata blocks are level 1; constant sparse defaults |
| R6 | major | Key-commitment claim too broad (HMAC equivalent keys); no offline oracle | §9.3: claim narrowed to fixed 32-byte keys |
| R7 | major | Revocation does not reach old snapshots | §2, §14: documented; MS rotation planned |
| R8 | minor | X25519 tell misdescribed; labels without suite; epoch start; metadata-block granularity; timing of slot trials; header key split | §7, §4.3, §5.2–5.4, §9.2 |

---

## 19. Implementation log (v0.1)

Where the code differs from, or fixes the details of, the text above. The
design stays the reference; each row says why the code won.

| # | Section | Change | Why |
|---|---|---|---|
| I1 | §4.3, §5.2, §9.3 | MAC labels are **length-prefixed** (`u8(len) ‖ label`) inside the HMAC input instead of bare concatenation. | With bare labels `…/n` is a prefix of `…/n1`, so `n ‖ u8(0x31) ‖ children` and `n1 ‖ block` are the same byte string. A length prefix makes the label set prefix-free by construction. |
| I2 | §9.3 | The key-commitment claim is about the **MAC key Km**. A different `Ka` or `Kc` with the same `Km` passes the tag and decrypts to other bytes. | Found by a test written to assert the opposite. It is harmless because every object is opened with all three keys derived together (one slot yields MS, one KEK yields three keys), and a test pins the exact statement. |
| I3 | §6.2, H2 | FIDO2 **locator slots are untagged** (TA1 keystream only), like Shamir share slots. | A tagged locator sealed under the password KEK would confirm a password guess offline without the key, which is exactly review finding R3. Unlock decrypts each candidate locator and lets the key (or the pairwise slot's tag) be the only verifier. |
| I4 | §6.1 | The Argon2id table is a package variable in `internal/kdf` so tests can substitute small profiles. No production code writes it, and the profile still comes only from the user's hint. | A 2 GiB derivation per test is not possible in CI. |
| I5 | §4.3 | The RFC 9106 §5.3 vector (which uses a secret and associated data that x/crypto's `IDKey` does not accept) is checked against a naive Argon2id written from the RFC in the test, and that reference is then compared with `IDKey` on three parameter sets. | `IDKey` cannot take those inputs, so the vector cannot be run on it directly. |
| I6 | §2, §6.2 | `kdf.Keys` expands one 32-byte KEK into Kc, Ka and Km with a **single** 96-byte HKDF call; `kdf.Pair` sorts the two kinds itself; `ta1.MAC` accepts only the tree labels and panics otherwise. | Found by review of PR #3: the claim "one KEK yields three keys" (I2) needed code to stand on, a pair key must not depend on argument order, and a generic MAC entry point with the leaf or seal labels would have shared a tag namespace with sector and object tags. |
| I7 | §10.1 | `Argon2id` refuses a profile whose memory does not fit the platform's `int` (2 GiB on a 32-bit target). | A hint-selected 2 GiB profile on 386/arm would crash in the allocator. |
| I8 | §5.2, §9.1 | A never-written sector inside a **written** metadata block carries a random seed and the tag `HMAC(Km, label(unwritten) ‖ cid ‖ u64(i) ‖ r)[0:24]` (`ta1.UnwrittenTag`), checked before any data read; the reader returns zeros. | The text leaves open how such a sector is marked. All-zero entries would show an attacker holding one snapshot exactly which sectors were written. This entry is indistinguishable from a written one without Km. |
| I9 | §5.3 | Journal slots are fixed 4352-byte entries (sealed record plus random padding, the padding unauthenticated and ignored). Recovery stops at the first entry that is neither a valid record nor the matching commit, and accepts only a transaction for exactly header epoch + 1. | Fixes the journal's concrete layout; the replay, reorder, drop, splice and torn-write cases are tests. |
| I10 | §5.3 | `journal.Recover` authenticates the commit root but cannot recompute it; the container checks the on-disk root after applying a replayed transaction. A `Write` that fails after the commit entry may have committed: the caller recovers before reusing the epoch. The tree's node cache is unbounded in v0.1 (up to 2^27 level-2 nodes at the size cap): an eviction policy is a known gap. | Findings of the review of PR #3 (second implementation PR). |
| I11 | §9.1 | Tree nodes are plain HMAC values (not encrypted), and the constant `D(l)` of an unwritten child repeats inside them. A container at rest is indistinguishable from random **except the tree area**, which shows how sparse the container is (which 64-sector groups were ever written). The randomness test excludes the tree area and says so. | A consequence of §5.2's constant defaults that §9.1 did not state. Encrypting nodes would defeat "a parent records D(l) for untouched children" (the defaults would no longer be constants a reader can compare). Accepted for v0.1; to revisit with the log-structured layout (v0.3). |
| I12 | §5.3 | The container commits on its own when a write would overflow the journal. A single `WriteAt` that spans more sectors than one transaction holds is therefore **several** atomic transactions, not one. | The journal size is fixed at creation (default 64 entries); each transaction is atomic, and the crash test cuts every backing write of one transaction. |
| I13 | §6.2, H2 | Unlock decrypts every one of the 16 slots as a locator under each partner KEK and asks the key about **every** candidate: there is no shape test, every byte string decodes to a locator (credential id length = first byte mod 128, plus 1; flag bits masked), so a key is asked 16 times per partner factor presented. The key answers `NO_CREDENTIALS` without consuming the UV token (HARDWARE-KEYS §5.1), so this costs requests, not touches. | A consequence of untagged locators (I3). An earlier draft filtered candidates by shape; review of PR #4 (finding 1) showed the filter leaked about 3 bits of every offline password guess, since a wrong KEK yields a "plausible" locator only some of the time. |
| I14 | §5.4 | The rollback counter is an interface (`Counter`: handle, name, read, increment) and the mount protocol of §5.4 is implemented and tested against a software counter: bound `b == c` or `c+1`, header rebind then increment, explicit `AcceptRollback`. A container with no counter says so (`Info.RollbackProtected == false`). A TPM implementation is not part of v0.1: go-tpm2/tpm2 has no `NVIncrement` and there is no TPM on the development machine to test against, so it is not faked. | See go-tpm2/tpm2#15 (`NVIncrement`). |
| I15 | §2, §10 | Slot writes are ordered so that a crash can only leave a slot that is **recorded but holds random bytes**, never a working slot the header does not record. Adding: reserve the index, commit the header, then write the slot. Removing: overwrite the slot with random bytes, flush, then commit the header that frees it. `RemoveSlot` accepts any index 0..15, recorded or not, so a working unrecorded slot can still be destroyed. The API documents that older copies still open with a removed factor (R7). | Review of PR #4, finding 3: the first implementation had both orders backwards, and a crash left a working slot nothing could list or remove. A test cuts the power at every backing write of both operations. |
| I16 | §5.4 | Mount is split in two. The read-only half (identify the counter, read it, accept or refuse) runs **before** journal recovery, so a refused image is left byte-for-byte untouched. The writing half runs after recovery. When `b == c+1`, it finishes the earlier increment **and then** rebinds the header to the new `c+1` and increments again, like any mount. | Review of PR #4, findings 4 and 2. Without the rebind, the counter would end equal to the bound written by the crashed mount, and an image copied during that crashed session would still be accepted at the next mount. A counter at 2^64−1 cannot be rebound and is refused. |
| I17 | §13 | Secrets are wiped on every path: the master secret when `Create` fails; derived factors when collecting them fails; duplicate FIDO2 answers are detected by comparing derived KEKs, not by keeping the raw secret as a (non-wipeable) map key. The recovery code is classified, checksummed and decoded in constant time: no early exit, no table indexed by a character, a single comparison; the only public quantities that end work early are the length and the separator positions. A test and a fuzz target check it against a straightforward parser. | Review of PR #4, findings 5 and 7. |
| I18 | §6.2, H2 | `EnrollFIDO2` checks that the container is usable and has two free slots per partner **before** asking the key (no touch is spent on an enrolment that cannot be stored), does not hold the container lock during the touch, and records all its slots with **one** commit. A refused enrolment leaves no reservation behind. | Review of PR #4, finding 6: the earlier version added slots one commit at a time and could stop half-way. |
| I19 | §6.2, H2, R3 | Every bit of a locator that is not data is random padding, including the 6 non-flag bits of the flags byte. **Known limit, open:** the data itself can be predictable. If the authenticator model gives credential IDs a fixed length, the length byte (7 bits) of the real locator is known to an attacker, and a wrong password guess makes some slot decrypt to that length with probability `1 − (127/128)^16 ≈ 12 %`: about 3 bits of offline filtering per guess, at full Argon2id cost per guess, with no key present. Any fixed structure inside the credential ID adds to it (HARDWARE-KEYS lists the YubiKey format as unknown). | Review 2 of PR #4: the flags byte was written whole, so those 6 bits were always 0 (≈2.2 bits per guess). The test now reads the decrypted bytes, not `OpenLocator`'s output. The length leak is a property of sealing a predictable plaintext under a password-derived key (H2), so it is not fixed in code: see the open question in the PR. |
| I20 | §5.4, §13, §10.1 | Stated limits. **One counter per container**: two containers bound to one counter refuse each other as rollbacks. `Unlock.Recovery` is a Go string and cannot be wiped; the parser itself copies it only into a wiped array. `freeSlot` gives up after 64 rejected draws (probability < 2^-64 from a working source). The verified **metadata block cache** grows like the node cache (I10), to 1/64 of the volume after a full `Verify`; an eviction policy is a known gap (go-theca/theca#6). `RemoveSlot` takes an index, and the public API has no call yet that maps a factor to its slot or that refuses to remove the last slot that opens the container (go-theca/theca#5), to settle before the CLI exposes removal. | Review 2 of PR #4. |
