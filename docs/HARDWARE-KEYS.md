# Hardware keys: unlocking with a YubiKey Bio (fingerprint)

Status: **design note**, 2026-11-15. No code. It complements the main design
document (`docs/DESIGN.md`, pull request #1, §6.2–6.3), which it does not
change.

Goal: the go-fde drivers (Theca, VeraCrypt, ZED!) unlock with a **YubiKey Bio
– Multi-protocol Edition**, with the fingerprint as user verification, in pure
Go (`CGO_ENABLED=0`, no libfido2, no cgo PC/SC).

Conventions. Every claim carries its source. **Opened** means the page or file
was read for this note on 2026-11-15. The list of what could **not** be opened
is in §10. A source that was not opened is not evidence of absence.

---

## 1. Summary

| Driver | Mechanism | Library work | Verdict |
|---|---|---|---|
| Theca | Native FIDO2 `hmac-secret` slot, F2 of the 2-of-3 | Add `hmac-secret`, `credProtect` and the UV token to **go-authn/fido** (exists) | Feasible; the transports exist on macOS and Linux |
| VeraCrypt | A keyfile derived in memory from the `hmac-secret` output | Same as Theca, plus a small sidecar for the credential ID | Feasible in **our** driver only. **VeraCrypt itself cannot open such a volume**: it has no FIDO2 support |
| ZED! Enterprise | PIV RSA private-key operation on the key, fingerprint by PIV PIN policy `MATCH-*` | New PC/SC transports and a PIV protocol package; ZED!'s RSA-user format is unknown | Feasible on the key side; **blocked on the ZED! format**, which nobody has documented |

The fingerprint never leaves the key. What the host sees is a **UV flag**, and
**the PIN is always an equal alternative to the finger**, in FIDO2 and in PIV
alike (§2.2, §4.2). Nothing on the wire says which one was used. This is the
most important fact for the threat model (§8).

---

## 2. FIDO2 / CTAP

Source: FIDO Alliance, *Client to Authenticator Protocol (CTAP) v2.1*,
Proposed Standard with errata, 2022-06-21,
<https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html>
(opened; read in windows of the HTML). CTAP 2.2, Proposed Standard 2025-07-14,
<https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html>
(opened, §11 and §12 only).

### 2.1 `hmac-secret` (CTAP 2.1 §12.5; CTAP 2.2 §12.7, `#sctn-hmac-secret-extension`)

- At `authenticatorMakeCredential` the authenticator generates **two** random
  32-byte values per credential, `CredRandomWithUV` and `CredRandomWithoutUV`
  (2.2 §12.7).
- At `authenticatorGetAssertion` the platform sends a map: `keyAgreement`
  (0x01, the platform's ECDH public key), `saltEnc` (0x02, `salt1` or
  `salt1 ‖ salt2`, 32 bytes each, encrypted under the shared secret),
  `saltAuth` (0x03, authenticates `saltEnc`), and `pinUvAuthProtocol` (0x04),
  which a CTAP 2.1 platform MUST include when the protocol is not 1 (2.1
  §12.5).
- The output is `HMAC-SHA-256(CredRandom, salt1)` (and the same for `salt2`),
  returned **encrypted** under the shared secret: 32 or 64 bytes (2.1 §12.5).
- **Which `CredRandom`:** "If uv bit is set to 1 in the response, let
  CredRandom be CredRandomWithUV", otherwise `CredRandomWithoutUV` (2.1
  §12.5). An assertion made without UV yields a **different** secret. It is not
  an error. A driver that enrols with UV and unlocks without it gets a wrong
  key, not a refusal.
- CTAP 2.2 adds `hmac-secret-mc` (§12.8, `#sctn-hmac-secret-make-cred-extension`):
  the same output at `MakeCredential`, which saves the second touch at
  enrolment. It requires `hmac-secret: true` in the same request. Whether the
  Bio's firmware supports it is **unknown** (its `GetInfo` must be read).

### 2.2 User verification on a Bio key

- `getPinUvAuthTokenUsingUvWithPermissions` (authenticatorClientPIN
  subcommand **0x06**, 2.1 §6.5.5.7.3): the authenticator performs **built-in
  UV**, the fingerprint on a Bio. The steps do not take a PIN. It returns
  `CTAP2_ERR_NOT_ALLOWED` if built-in UV is supported but not configured (no
  finger enrolled), `CTAP2_ERR_UV_INVALID` on a mismatch,
  `CTAP2_ERR_UV_BLOCKED` when `uvRetries` reaches 0, and
  `CTAP2_ERR_USER_ACTION_TIMEOUT`. After `UV_BLOCKED` "the platform MAY fall
  back" to `getPinUvAuthTokenUsingPinWithPermissions`.
- The `uv` option of `GetAssertion` is **deprecated in CTAP 2.1**. Platforms
  SHOULD obtain a `pinUvAuthParam` through the two token subcommands (2.1 §6.2,
  `#getassert-uv`). When a `pinUvAuthParam` is present, the authenticator
  treats `uv` as false (§6.2.2 step 4.2), so the two are never sent together.
- A token is spent by the operation it authorises: after a successful
  `GetAssertion` its permissions are cleared except `lbw` (§6.2.2 step 9.4).
  Each assertion therefore needs a fresh token, which means **a fresh finger**.
- Retry counters: `maxUvRetries` is 1 to 25, and a successful built-in UV resets
  `uvRetries`. `pinRetries` allows at most 8, and at 0 both ClientPIN **and
  built-in UV** are disabled until reset (2.1 §6.5.2.2, §6.5.3.1). The modality
  value for a fingerprint is 0x01 (2.1 §6.7).
- Yubico, for the Bio series: "Three consecutive failed matches block
  fingerprint recognition, and the key falls back to the PIN". Up to 5
  fingerprints. The FIDO2 PIN has no default, three wrong PINs in a row require
  re-insertion, eight lock the FIDO2 application
  (<https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-bio-specifics.html>,
  opened).

**Answer to the question asked:** yes, the fingerprint alone satisfies UV
through subcommand 0x06, with no PIN typed. But a PIN is set on every Bio key
(it is the fallback), and **a PIN-verified assertion also sets UV**, so it
yields the same `CredRandomWithUV` and the same secret. "Fingerprint only" is
not a property the host can enforce.

### 2.3 Credential creation: discoverable or not, `credProtect`

- A discoverable credential is created "if, and only if" the `rk` option is
  true. Otherwise the authenticator "MUST create a non-discoverable credential"
  (2.1 §6.1.3, §6.1.2 step 18). Platforms MUST NOT send `rk` to `GetAssertion`
  (2.1 §6.2).
- `credProtect` (2.1 §12.1): level 1 `userVerificationOptional` (the default),
  level 2 `userVerificationOptionalWithCredentialIDList`, level 3
  `userVerificationRequired`, under which the credential can be neither
  discovered nor **used** without UV.
  `enforceCredentialProtectionPolicy` makes creation fail rather than silently
  fall back to a lower level.

**Choice for disk unlock: non-discoverable, `credProtect = 3`, enforced.**

- Non-discoverable: it consumes no slot on the key (the Bio holds 25
  discoverable credentials before firmware 5.7 and 100 after, Yubico page
  above), it allows one credential per container without limit, and it is what
  systemd does (§3.1). The cost is that the credential ID must be stored next to
  the container (§5.1).
- Level 3: without UV the credential does not answer at all, so the
  `CredRandomWithoutUV` path cannot even be probed.

### 2.4 CTAPHID framing (CTAP 2.1 §11.2)

- Initialisation packet: CID (4 bytes), CMD (1 byte, bit 7 set), BCNTH, BCNTL,
  then data from offset 7. Continuation packet: CID, SEQ (0x00–0x7F), data from
  offset 5. With 64-byte reports the largest message is **7609** bytes
  (§11.2.4).
- Commands: `INIT` 0x06, `PING` 0x01, `MSG` 0x03, `CBOR` 0x10, `CANCEL` 0x11,
  `KEEPALIVE` 0x3B, `ERROR` 0x3F, `WINK` 0x08, `LOCK` 0x04 (§11.2.9.1–2).
- `KEEPALIVE` carries one status byte, `STATUS_PROCESSING` (1) or
  `STATUS_UPNEEDED` (2). It is sent at least every 100 ms and **does not end the
  transaction** (§11.2.9.1.7).
- `CANCEL` (BCNT 0) gets no reply of its own. The pending request answers
  `CTAP2_ERR_KEEPALIVE_CANCEL` (§11.2.9.1.5). The driver sends it when the
  context is cancelled or the prompt times out (§7).

All of this is **already implemented and tested** in go-authn/fido (§6).

---

## 3. Prior art

### 3.1 systemd-cryptenroll and the LUKS2 `systemd-fido2` token

Sources: the man page
<https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html>
(opened, section "FIDO2 Enrollment"); `src/cryptenroll/cryptenroll-fido2.c`
and `src/shared/libfido2-util.c` on systemd `main`
(<https://github.com/systemd/systemd>, opened 2026-11-15).

- **rp id**: a constant, `"io.systemd.cryptsetup"`, with rp name
  `"Encrypted Volume"`. The user ID and name are the disk's UUID
  (`enroll_fido2()`).
- **salt**: random unless `--fido2-salt-file` names a file or an `AF_UNIX`
  socket. `fido2_generate_hmac_hash()`'s comment says "a salt of 32 bytes".
  Only `salt1` is used, never `salt2`.
- **Credential**: `rk` forced **false** when the device knows the option.
  `hmac-secret` always requested. `credProtect = UV_REQUIRED` **only** when UV
  locking is asked for, and a failure to set it is only a warning ("ignoring").
  Enrolment makes a credential, then a **second** assertion to obtain the
  secret.
- **Flags and defaults**: `--fido2-with-client-pin` yes,
  `--fido2-with-user-presence` yes, `--fido2-with-user-verification` **no**,
  `--fido2-credential-algorithm` es256 (man page).
- **Token JSON** (`enroll_fido2()`): `type: "systemd-fido2"`, `keyslots`,
  `fido2-credential` (base64 credential ID), `fido2-salt` (base64),
  `fido2-rp`, `fido2-clientPin-required`, `fido2-up-required`,
  `fido2-uv-required`. With `--fido2-parameters-in-header=no`, nothing is
  written and the credential ID goes into `/etc/crypttab` (`fido2-cid=`).
- **Key**: the `hmac-secret` output, **base64-encoded**, is the LUKS keyslot
  passphrase. A comment explains that cryptsetup wants a passphrase.

Lessons we take: non-discoverable credential, a fixed rp id, a 32-byte salt
stored beside the credential ID, and recorded flags so that unlock asks for
what enrolment used. Lessons we do **not** take: UV off by default, and a
`credProtect` that may silently not be applied (we enforce it, §2.3).

### 3.2 VeraCrypt: PKCS#11 keyfiles only

Sources: "Security Tokens & Smart Cards",
<https://veracrypt.io/en/Security%20Tokens%20%26%20Smart%20Cards.html>, and
"Keyfiles", <https://veracrypt.io/en/Keyfiles%20in%20VeraCrypt.html>
(both opened).

- VeraCrypt supports "tokens and smart cards that can be accessed using the
  PKCS #11 (2.0 or later) protocol". It "can directly use keyfiles stored on a
  security token or smart card", which must let the user "store a file (data
  object)" on it. That file is a plain keyfile behind the token's PIN.
- Tokens are "currently not supported for Pre-Boot authentication".
- EMV cards: data read from the card used as a keyfile, off by default.
- Keyfiles between 64 bytes and 1 MiB; the generator's default is 64 bytes.
- **Nothing about FIDO2**, and the token's own cryptography is not used. The
  token only stores a file.

### 3.3 piv-go (the reference pure-Go PIV client)

Source: <https://github.com/go-piv/piv-go>, default branch `v2`, last push
2026-04-15 (opened through the GitHub API).

- **It uses cgo on every Unix.** `v2/piv/pcsc_unix.go`: build tag
  `darwin || linux || freebsd || openbsd`, `#cgo darwin LDFLAGS: -framework
  PCSC`, `#cgo linux pkg-config: libpcsclite`, `#include <PCSC/winscard.h>`,
  `import "C"`. There is no purego path.
- **On Windows it is already pure Go**: `pcsc_windows.go` loads
  `Winscard.dll` through `syscall.NewLazyDLL` (`SCardEstablishContext`,
  `SCardListReadersW`, `SCardConnectW`, `SCardTransmit`, …).
- It supports the Bio policies: `bio_integration_test.go` generates keys with
  `PINPolicyMatchOnce` and `PINPolicyMatchAlways` and signs, gated behind
  `PIV_BIO_TESTS=1` and `--wipe-yubikey`, printing "touch/biometric required"
  to stderr. That is the human-in-the-loop pattern of §7.3.

---

## 4. YubiKey Bio – Multi-protocol Edition

### 4.1 Applications

Source: the Yubico Bio page above (opened). FIDO2, FIDO U2F and **PIV**. The
page does not mention OTP, OpenPGP or OATH, so they are **unknown**, not
absent. The PIN is **shared between FIDO2 and PIV**: 6 to 8 characters while
PIV is enabled. The PUK is blocked by default, so a blocked PIV PIN means a
reset. One combined reset replaces the native FIDO and PIV resets, and
protocols can be enabled or disabled only on a freshly reset device. USB PID
0x0402, product string "YubiKey FIDO".

### 4.2 PIV with the fingerprint

- Two PIN policies exist for the Bio: **Match Once** ("a biometric or PIN
  verification is required for each session") and **Match Always** (the same
  "for every key operation"), firmware 5.7 or later, Multi-protocol Edition only
  (Yubico .NET SDK manual, "PIV PIN, touch and bio policies",
  <https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html>,
  opened). The policy is chosen at generation or import.
- ykman: `ykman piv keys generate --pin-policy` takes `DEFAULT, NEVER, ONCE,
  ALWAYS, MATCH-ONCE, MATCH-ALWAYS`
  (<https://docs.yubico.com/software/yubikey/tools/ykman/PIV_Commands.html>,
  opened; that page does not define the MATCH values).
- On the wire (yubikit's `piv` module,
  <https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/piv.html>,
  opened): `PIN_POLICY.MATCH_ONCE = 0x4`, `MATCH_ALWAYS = 0x5`. `verify_uv`
  sends **VERIFY (INS 0x20) with P2 0x96**, empty data to check only, `Tlv(3)`
  to ask for a match, or `Tlv(2)` to ask for a **16-byte temporary PIN**.
  `verify_temporary_pin` sends `Tlv(1, pin)` to the same P2. `get_bio_metadata`
  is INS 0xF7, P2 0x96.
- On Windows, fingerprint use for PIV needs Yubico's Smart Card Minidriver
  4.6.0 or later. When a fingerprint fails, "enter the YubiKey PIN" (Yubico
  Bio page).

### 4.3 PIV key types

yubikit `KEY_TYPE`: RSA1024 (0x06), RSA2048 (0x07), RSA3072 (0x05), RSA4096
(0x16), ECCP256 (0x11), ECCP384 (0x14), ED25519 (0xE0), X25519 (0xE1).
`_do_check_key_support` requires firmware **5.7.0** for RSA3072, RSA4096,
Ed25519 and X25519. The ykman page lists the same eight algorithms, with RSA2048
as the default. The Bio's PIV policies themselves require 5.7, so a Bio with PIV
has firmware ≥ 5.7. Inference, not verified on a device: the Bio MPE supports
all eight.

---

## 5. How each driver uses it

### 5.1 Theca: a native FIDO2 slot as F2

This fits DESIGN.md §6.2 (F2 "hardware-bound") and both constructions of
decision D3.

> **Revised.** H2 (a) was replaced on 2026-11-15 by (b) ("H2 revised" in §9,
> DESIGN.md §19 I21). Read this section with these changes:
>
> - step 2 uses `rk = true`;
> - step 3 has no stored `salt_c`: the salt is derived from the partner;
> - there is no locator;
> - the **Unlock** paragraph sends an empty `allowList` and reads every Theca
>   credential through `getNextAssertion`, instead of trying stored credential
>   IDs;
> - in §8.4, "the credential is the one asked for" becomes "one of the
>   credentials returned".
>
> `GetInfo`, `credProtect`, the UV and UP checks and the KEK derivation are
> unchanged.

**Enrolment** (needs MS, so two factors present, DESIGN.md §6.2):

1. `GetInfo`. Require `hmac-secret` in `extensions`, `credProtect` support,
   and `uv: true` (built-in UV configured) or `clientPin: true`.
2. `MakeCredential` with `rp.id = "theca"` (§8.2), `user.id` = 16 random
   bytes (never anything that names the person or the container), `rk = false`,
   `alg = ES256`, extensions `hmac-secret: true` and `credProtect: 3` with
   `enforceCredentialProtectionPolicy`. Authorised by a UV token (subcommand
   0x06, permission `mc`) or by a PIN token as the fallback.
3. Choose `salt_c` = 32 random bytes, stored in the slot's sealed locator, and
   compute `salt1 = SHA-256("theca/v1/fido2/salt" ‖ salt_c)`. The salt is fixed
   for the slot's life and does not depend on the header salt (decision H7,
   §9). The binding to the container comes from the locator, which is sealed
   under the partner factor's KEK (§8.3).
4. `GetAssertion` with `allowList = [credID]`, the `hmac-secret` input, and a
   UV token with permission `ga` and `rpId = "theca"`. Check `UV = 1` **and**
   `UP = 1` in the returned flags, refuse otherwise. Steps 2 and 4 each spend a
   token (§2.2), so enrolment asks for **two fingers**. `hmac-secret-mc` (2.2
   §12.8) would make it one, but the YubiKey 5.7.4 `GetInfo` capture in
   go-authn/fido does not list it (§10).
5. `KEK₂ = HKDF(output1, info = "theca/v1/TA1/slot/fido2")`, then the slot
   is sealed exactly as the other factors are (TA1, DESIGN.md §6.2).

**The FIDO2 locator**: credential ID, `salt_c`, and a flags byte (UV
required, PIN protocol). There is no rp id: it is a constant of the format.

**Unlock**: take the UV token **first** (one finger, subcommand 0x06,
permission `ga`), then try each stored credential ID with that token. Probing
before UV does **not** work under `credProtect = 3`: a
userVerificationRequired credential is removed from the candidates when the uv
bit is false (2.1 §6.2.2 step 7.4), and the request answers `NO_CREDENTIALS`
(step 7.6) on the right key exactly as on the wrong one. With the token, a
wrong ID stops at step 7 and does not spend the token, which is only consumed
at step 9.4. Then derive KEK₂ and trial-open as for any other slot. Note also
that `up = false` with `hmac-secret` is refused with `UNSUPPORTED_OPTION`
(§12.5).

**Header indistinguishability (Theca has no magic, DESIGN.md §9.1).** Under
2-of-3 there is no lone "F2 slot": with pairwise slots (D3 (b)) MS is wrapped
under HKDF(KEK_a ‖ KEK_b), and with Shamir (D3 (a)) share slots are untagged.
A locator in clear (a credential ID of fixed length, a flags byte) would be a
tell. Decision **H2**:

- (a) **Seal the locator under the partner factor's KEK** (recommended). For
  the pair {password, key} it is sealed under KEK₁, for {key, recovery code}
  under KEK₃, with TA1 like every slot. Argon2id runs first in any case
  (DESIGN.md §9.2), so the locator is found by trial decryption of
  random-looking bytes and the header keeps no magic. The cost is one locator
  per pair that includes F2, so two sealed locators per key, and the 16-slot
  budget must be re-counted when two keys are enrolled (§8.5).
- (b) Make the credential **discoverable** (`rk = true`, `rpId = "theca"`) and
  store nothing that names it. Unlock then asks the key for every `theca`
  credential (empty `allowList`, after UV) and tries each. The cost is a slot
  on the key per container (25 or 100 in total), and the key reveals, to anyone
  holding it with UV, that `theca` credentials exist.
- (c) Store the credential ID in clear. This holds only if credential IDs are
  indistinguishable from random **and** of a length every slot shares. Not
  recommended: the format of Yubico's IDs is undocumented in what was opened
  (the 5.7.4 capture gives only `maxCredentialIdLength = 128`).

### 5.2 VeraCrypt: a keyfile derived from `hmac-secret`

go-fde/veracrypt unlocks with "password, keyfiles and PIM" (repository
description). VeraCrypt's own keyfile processing is unchanged. We feed it a
keyfile **computed in memory**:

```text
salt1   = SHA-256("go-fde/veracrypt/fido2/v1" ‖ salt_v)
keyfile = HKDF(hmac_secret_output1, info = "go-fde/veracrypt/keyfile/v1", 64 bytes)
```

`salt_v` is 32 random bytes stored in a **sidecar** (`<volume>.fido2`, a
small versioned file holding the credential ID, `salt_v`, rp id and flags).
The volume's own header salt is **not** used. It is not always at offset 0:
system encryption puts the header at byte 31744, hidden volumes at 64 KiB, and
there is a backup header (go-fde/veracrypt `veracrypt.go`). Changing the
password may also re-salt the header (not verified), and that would silently
change the keyfile. The sidecar already has to exist for the credential ID,
unless the credential is discoverable (the same trade-off as Theca's H2 (b)).

**Say it plainly in the README: VeraCrypt itself cannot open such a volume.**
VeraCrypt has no FIDO2 code (§3.2). The only way to open it in VeraCrypt is to
export the derived keyfile to disk, which removes the protection the key gave.
That is offered only as an explicit `export-keyfile` escape hatch, with a
warning.

An alternative that **VeraCrypt can** open: a keyfile stored as a **PKCS#11
data object** on the token (§3.2), through Yubico's PKCS#11 module. Its
protection is the shared PIN, not the finger, the keyfile is stored in clear on
the token, and whether ykcs11 exposes writable data objects on the Bio is
**unknown**. Not recommended; listed for completeness.

### 5.3 ZED! Enterprise: PIV RSA, feasibility only

go-fde/zed reads password users only. "RSA users" are out of scope, and an
archive with none returns `ErrUnsupported` (go-fde/zed README, opened).

Key side, feasible:

- The Bio MPE holds RSA 2048 to 4096 keys in PIV slots (§4.3), with a
  `MATCH-ONCE` or `MATCH-ALWAYS` policy (§4.2). The fingerprint is asked through
  VERIFY P2 0x96. The decryption is a PIV GENERAL AUTHENTICATE with the raw
  RSA private-key operation, the padding being checked by the host (piv-go does
  this for `crypto.Decrypter`; standard PIV, NIST SP 800-73-4 Part 2, **not
  opened** for this note).
- Transport: PC/SC (§6.3).

Format side, **blocked**: how ZED! wraps the archive key for an RSA user (the
TLV items, the padding, PKCS#1 v1.5 or OAEP, the certificate reference) is not
in Beucler's document as far as go-fde/zed's README records, and the SSTIC 2024
paper was not opened for it. It needs one real Enterprise archive with an RSA
user, and the matching certificate, to reverse with the same Directive
2009/24/EC basis the zed README states. No hardware work should start before
that.

---

## 6. Where the code goes

### 6.1 What already exists (verified 2026-11-15)

`fleetfind` over 2253 repositories (names and descriptions):

| Query | Matches |
|---|---|
| `hid` | go-gnulinux/factors, go-gnulinux/fido, go-macos/fido, go-macos/iokit, go-mswin/webauthn |
| `ctap` | go-mswin/webauthn |
| `fido` | go-authn/fido, go-gnulinux/fido, go-macos/fido, go-mswin/webauthn |
| `iokit` | go-macos/iokit |
| `piv`, `pcsc`, `cbor` | **none** |

`priorart --repo go-theca/theca "fido2"`: clean (tracker and branches).

- **go-authn/fido** v0.6.4 (2026-11-08), BSD-3-Clause, CBOR through
  `fxamacker/cbor` with `CTAP2EncOptions`. It has CTAPHID framing (`Split`,
  `Reassembler`, KEEPALIVE skipped, 7609-byte limit), `GetInfo` (decoded
  against a capture from a YubiKey 5.7.4), `MakeCredential`, `GetAssertion`,
  `AuthData` parsing (including the raw extension output), and ClientPIN
  protocols 1 and 2 (`PINRetries`, `KeyAgreement`, `PINToken` with
  permissions). 100% coverage with a fake transport, and it has run against a
  real YubiKey 5.7.4 (README; `credential.go`, `clientpin.go`, read in a clone).
- **go-macos/fido**: IOKit HID transport through go-macos/iokit (purego), pure
  Go. **go-gnulinux/fido**: hidraw transport, no libudev, tested end to end
  against a kernel-made `/dev/uhid` device in CI, **never against a real key**
  (its README says so).
- **go-mswin/webauthn**: Windows through `webauthn.dll`. Raw FIDO HID needs
  elevation since Windows 10 1903, so it is not a CTAP transport (its README).
- **go-authn/keyfactor**: a security key as a go-authn/mfa factor. Its tests
  play the authenticator's side of PIN protocol 2 **independently**.
- **go-macos**: no CryptoTokenKit binding, no PC/SC (repository list).

### 6.2 Gaps in go-authn/fido (no new repository needed for FIDO2)

Read in `credential.go` and `clientpin.go`:

1. **No extensions parameter**: `MakeCredentialRequest` and
   `GetAssertionRequest` have no field for map key 0x06 (MC) and 0x04 (GA).
   Add `hmac-secret`, `credProtect` (with enforcement) and, later,
   `hmac-secret-mc`.
2. **No UV token**: `subGetTokenUsingUV = 0x06` is declared but unused. Add
   `UVToken(ctx, proto, perms, rpID)`, with `UV_BLOCKED` and `NOT_ALLOWED`
   reported as distinct errors so that a caller can offer the PIN fallback
   knowingly.
3. `hmac-secret` decryption of the output, sharing the PIN protocol code
   (`pinproto.go` already has both protocols' `encrypt`, `decrypt` and
   `authenticate`).
4. A test that plays the **authenticator's** side of `hmac-secret`, written
   from the specification and not from the client (the keyfactor pattern).

The CTAP2 library therefore stays in **go-authn/fido**: it is OS-agnostic,
already has the framing, CBOR and PIN protocols, and go-authn is where the
other consumers (keyfactor, mfa) live. A new repository would be a second copy.

### 6.3 New repositories (waiting for go-ahead; `ghnew` not run)

PIV and PC/SC have nothing in the fleet. The proposal mirrors the FIDO
layering (protocol in go-authn, transport per OS):

| Repository | Content | Why there |
|---|---|---|
| **go-authn/piv** | PIV APDUs over an abstract `Card` (transmit APDU, get response): SELECT, VERIFY (including P2 0x96 bio), GENERAL AUTHENTICATE, metadata, Yubico extensions. No OS code | Same place and shape as go-authn/fido |
| **go-macos/pcsc** | PCSC.framework through purego (`SCardEstablishContext`, `SCardTransmit`, …) | go-macos already binds frameworks through purego (iokit, keychain) |
| **go-gnulinux/pcsc** | A **pcscd client speaking its UNIX-socket protocol** directly, or `libpcsclite.so` through purego | No cgo either way; the socket protocol needs no shared library. Its wire format was not opened (§10) |
| **go-mswin/winscard** | `Winscard.dll` through `syscall` | piv-go proves this path is pure Go already (§3.3) |

Alternative: one `go-authn/pcsc` with per-OS files, as piv-go does. Fewer
repositories, but it breaks the "platform code lives in its platform org"
pattern that go-authn/fido established. **Decision H4.**

### 6.4 Transport plan per OS

| OS | FIDO2 | PIV |
|---|---|---|
| macOS | go-macos/fido: IOKit HID, usage page 0xF1D0, purego. No entitlement needed (its README) | go-macos/pcsc (new). CryptoTokenKit is the other route, but it is Objective-C and exposes tokens as keychain items, which is heavier and not needed |
| Linux | go-gnulinux/fido: hidraw, needs the `70-u2f` udev rule for a non-root user | go-gnulinux/pcsc (new), requires `pcscd` running |
| Windows (later) | go-mswin/webauthn: `webauthn.dll`. Whether it exposes `hmac-secret` salts to an unelevated caller, and from which API version, is **not opened** (§10). The fallback is elevation, which we do not ship | go-mswin/winscard (new) |

---

## 7. Autonomous test plan

### 7.1 Without a key or a finger (CI, every pull request)

1. **Virtual authenticator** in go-authn/fido, package `fidotest`: a pure-Go
   CTAP2 authenticator answering CTAPHID reports, with `hmac-secret`
   (`CredRandomWithUV` and `WithoutUV`), `credProtect`, ClientPIN protocols 1 and
   2, built-in UV **simulated** (a test hook says "finger matched", "no match",
   "blocked", "timeout"), and KEEPALIVE `UPNEEDED` while it waits. It is written
   from the specification, by a different hand than the client, so that the two
   cannot agree on a shared mistake (keyfactor's rule).
2. **Spec-derived vectors**: compute `HMAC-SHA-256(CredRandom, salt)` and the
   protocol 1 and 2 encryption independently, and check the client's decryption.
3. **Recorded transcripts**: one-time captures from the real Bio (below),
   replayed by a fake transport. The platform's ECDH key and the salts must come
   from an injectable `io.Reader` so that a replay is deterministic. A
   transcript holds no secret worth keeping (test credential, test PIN), but it
   is still generated on a reset test key only.
4. **End to end on Linux CI**: the virtual authenticator behind `/dev/uhid`
   gives a real hidraw node (go-gnulinux/fido already does this for the
   handshake), so `theca unlock` runs against a device the kernel made.
5. **Drivers**: Theca and VeraCrypt tests use the virtual authenticator to
   enrol, unlock, refuse a wrong key, refuse `UV = 0`, refuse a different
   container's salt, and check that `CredRandomWithoutUV` yields a different
   KEK (the regression the spec makes possible, §2.1).
6. **PIV**: an APDU-level fake card, and transcripts as above. Fuzz the TLV and
   APDU response parsers (corpus committed).
7. **Fuzzing**: CBOR responses (`GetInfo`, `GetAssertion`, extension outputs)
   and CTAPHID reassembly, with go-authn/fido's existing `fuzz_test.go` as the
   home.

### 7.2 With a key, no finger (a machine with the Bio plugged in, unattended)

`GetInfo` capture (extensions, options `uv`, `bioEnroll`, `alwaysUv`,
`pinUvAuthToken`, `uvModality`, firmware), `Wink`, `PING`, and
`GetAssertion` against an unknown credential ID without a token (expects
`NO_CREDENTIALS`, no touch; with `credProtect = 3` the right ID answers the same,
§5.1). These are gated by `FIDO_KEY=1`.

### 7.3 With a finger (human in the loop)

Gated by `FIDO_HUMAN=1` (and skipped **loudly** otherwise, the skip naming the
variable), never in CI:

- The test prints to **stderr**, unbuffered: `FIDO: touch the fingerprint
  sensor of <key name> within 30 s (attempt 1/3)` and winks the key first, so
  that the right key is touched.
- Bounded by `context.WithTimeout(30 s)`. On expiry the client sends
  `CTAPHID_CANCEL` and the test fails with `timeout`, not a hang.
- Scenarios: enrol plus unlock (finger); a wrong finger (expects `UV_INVALID`,
  and the counter is read back); three wrong fingers then the PIN fallback
  (expects `UV_BLOCKED`, then the same secret through the PIN token, which proves
  §2.2's equality); PIV `MATCH-ALWAYS` sign twice (two prompts), as piv-go's
  `bio_integration_test.go` does.
- Destructive scenarios (reset, PIN change) also require `--wipe-key`.

---

## 8. Security considerations

### 8.1 What an attacker holding the key without the finger gets

- **With `credProtect = 3`**: the credential does not answer without UV. The
  attacker has **3 fingerprint attempts**, then the PIN: up to **8 PIN
  attempts**, after which FIDO2 and built-in UV lock until reset (§2.2). A PIN
  is 6 to 8 characters on an MPE with PIV enabled, so a short numeric PIN is the
  weak point. The fingerprint does not raise the bar above the PIN.
- **The PIN is shared with PIV** (§4.1). Whoever learns it for one learns it
  for both.
- A Theca slot needs **two** factors, so a key plus PIN alone opens nothing
  under 2-of-3. It reduces the problem to the other factor (DESIGN.md §6.2),
  which is why UV must be required on F2.
- A forged authenticator cannot produce the output without `CredRandom`. But it
  receives `LEFT(SHA-256(PIN), 16)` when the PIN fallback is used, which can be
  searched offline (go-authn/keyfactor README, "What it cannot protect").
  Prefer the finger, and never type the PIN into a key of unknown provenance.
- Malware on the host can ask the key for the output for **any** salt while
  the person touches it for something else. A UV token with permission `ga`
  is spent by one successful assertion (§2.2), but until then it can be used
  against any of the public stored salts, and the host's `UP = 1` check
  constrains nothing that malware does. This is inherent to `hmac-secret` and
  the same for systemd: the host running the unlock must be trusted.

### 8.2 rp id

A constant per format: `"theca"` for Theca, `"go-fde.veracrypt"` for
VeraCrypt. It is not a domain, so no browser can be tricked into asking for the
credential (WebAuthn binds the rp id to the page's origin; WebAuthn not opened
here), and it is not secret. systemd's choice of a fixed reverse-DNS string
supports the approach (§3.1). Per-container rp ids would be another tell in the
key and would buy nothing, because the salt already binds.

### 8.3 Salt handling and binding

- 32 bytes from `crypto/rand`, fixed per slot (H7). The binding to the
  container comes from the locator, sealed under the partner factor's KEK
  (H2), and from the TA1 slot itself (DESIGN.md §9.3). A random 256-bit salt
  per slot also makes the outputs for two containers unrelated, even with the
  same credential.
- ~~The salt is not secret.~~ **Since H2 was revised, the salt IS secret**: it
  is derived from the partner factor and verifies guesses of it at the
  partner's KDF cost. It is wiped after each call and never logged (§9, "H2
  revised"). The bullets above and below describe the stored random salt of
  H2 (a).
- Because `salt1` does not depend on the header salt (H7), re-salting the
  header (DESIGN.md §9.4) leaves KEK₂ unchanged and does not need the finger.
- `salt2` is reserved for rotation: asking for `salt1` and `salt2` in one touch
  derives the old and the new KEK together.
- The output is zeroised after HKDF (best effort in Go, as DESIGN.md §13 says
  for all key material).

### 8.4 What the host checks on every assertion

`UP = 1` and `UV = 1` in the returned flags. `rpIdHash = SHA-256(rp id)`. The
credential is the one asked for. The extension output decrypts under the shared
secret and has 32 or 64 bytes. Reply CMD and status were already checked by
go-authn/fido. A missing `hmac-secret` output is an error, never an empty key.

### 8.5 Availability

A single key is a single point of loss, so Theca's 2-of-3 keeps password plus
recovery code as the path without the key. For VeraCrypt, the volume keeps its
password, and the keyfile is **added** to it, never the only secret.
Recommendation: enrol **two** keys (two F2 slots).

---

## 9. Decisions for the user

- **H1** Accept that the PIN is an equal alternative to the finger (§2.2, §4.2),
  or require `alwaysUv` plus a long PIN policy? The host cannot force "finger
  only".
- **H2** Theca: the locator sealed under the partner factor's KEK
  (recommended), a discoverable credential, or the ID in clear (§5.1)?
- **H3** VeraCrypt: ship the FIDO2-derived keyfile knowing VeraCrypt cannot open
  it, with a sidecar file, or a discoverable credential?
- **H4** PIV and PC/SC layout: four repositories (§6.3), or one go-authn/pcsc
  with per-OS files? `ghnew` waits for this.
- **H5** ZED! Enterprise: obtain a real Enterprise archive with an RSA user
  before any PIV work, or build go-authn/piv for its own sake first?
- **H6** Windows: accept go-mswin/webauthn's dialog (Windows collects the finger
  or the PIN), subject to `hmac-secret` being reachable there (§10)?
- **H7** Theca: keep `header_salt` fixed for the container's life, or require
  the key at every header re-salt (§8.3)?

### Decisions (2026-11-15, author: user)

The recommendations were accepted.

- **H1**: yes, the PIN may replace the finger, as the standard requires. The UI
  says so, and the PIN must be strong.
- **H2**: the credential ID (the locator) is sealed under the partner factor's
  KEK.
- **H3**: yes, as an option. The VeraCrypt keyfile is documented as
  "unlockable only by our driver".
- **H4**: four repositories (go-authn/piv, go-macos/pcsc, go-gnulinux/pcsc,
  go-mswin/winscard), created later, not now.
- **H5**: wait for a real ZED! Enterprise sample before any ZED! PIV work.
- **H6**: use the Windows WebAuthn dialog.
- **H7**: the FIDO2 salt is fixed per slot and independent of the header salt.
  Rotating the header salt does not require the finger (§5.1, §8.3 updated).
  **Relaxed on 2026-11-16 by the user** with H2 revised: the `{password, key}`
  slot's salt now follows the password's KEK, so re-salting needs the key for
  that slot (see "H2 revised").

### H2 revised (2026-11-15, decision delegated by the user: « fait au mieux »)

**H2 is now (b), a discoverable credential, with a salt DERIVED from the
partner factor.** It replaces (a) above.

Why. Review 2 of go-theca/theca#4 showed that a locator sealed under a
password-derived key cannot hide a **predictable plaintext**: if a key model
gives its credential IDs a fixed length, the length byte alone lets a wrong
password guess be filtered offline, about 3 bits per guess, with no key
present (DESIGN 19, I19). Nothing in (a) can remove that, because the
locator has to be stored.

What changes:

- **No locator on disk.** The credential is discoverable (`rk = true`,
  `rpId = "theca"`, `credProtect = 3`). At unlock the key is asked once with an
  empty `allowList` and answers for every Theca credential it holds
  (`getAssertion`, then `getNextAssertion`).
- **The salt is derived, not stored:**
  `salt = HKDF-SHA-256(KEK_partner, info = "theca/v1/fido2/salt/<kind>")`, one
  per partner. The two salts (password, recovery code) travel in **one**
  request (`salt1`, `salt2`), so an unlock costs one touch. `salt2` is
  therefore no longer free for rotation (§8.3).
- **A wrong password gives a different salt.** Every guess therefore needs a
  fresh, touch-gated question to the key, even for an attacker who holds the
  key and its PIN. This keeps the property (a) had, that password guesses
  against the key slot are online only, and removes I19's offline filter
  entirely.
- **One slot per partner** instead of two (no locator slots).

**The salt is now a password verifier.** Being a function of the password,
it lets whoever READS it test password guesses offline, at one Argon2id per
guess (review of the change, finding 1, verified with a test). No design
removes every offline test; each moves it somewhere else:

| design | whoever holds the file | whoever holds the key and its PIN | whoever reads the salt (a forged key, a log, a memory dump) |
|---|---|---|---|
| (a) locator under KEK_pw | ~3 bits filtered per guess if credential IDs are predictable (I19) | online only | nothing to learn |
| (b), public salt | nothing | **full offline test** | nothing to learn |
| (b), salt derived from the partner (chosen) | nothing | online only | **full offline test** |

Why the last row. The host that sees the salt also sees the password typed
in, so a trusted host learns nothing new. What remains is a **forged
authenticator**, which receives the salt inside the hmac-secret request, and
**software hygiene**. Therefore the salts are wiped after each call
(`TestSaltsAreWipedAfterTheCall`), must never be logged, and the adapter
must not keep them.

What it costs, stated:

- **One discoverable credential per enrolment** on the key: 100 slots on
  firmware 5.7, 25 before.
- **A key held with its PIN reveals that Theca credentials exist on it.** The
  key does not reveal which containers they belong to.
- **H7 relaxed, decided by the user on 2026-11-16 (« prenons assoupli »),**
  after the trade-off was explained in concrete terms: protection against a
  thief holding the key, its PIN and a copy of the container (every password
  guess costs a touch) was preferred to re-salting without the key, an
  operation v0.1 does not have. H7 said the FIDO2 salt is "independent of the
  header salt". Here
  the salt of the `{password, key}` slot depends on the password's KEK, which
  depends on the header salt. So re-salting the header needs the key (one
  touch) for that slot. A password change already needs the key in practice.
  The `{recovery code, key}` slot is unaffected, because the recovery code's
  KEK does not depend on the header salt. Re-salting is not implemented in
  v0.1.
- **Touches.** One per unlock: `Derive` is one `getAssertion` plus
  `getNextAssertion` calls. **Two per enrolment** unless the key supports
  `hmac-secret-mc`: `makeCredential`, then `getAssertion` for the outputs
  (§5.1 step 4). The 5.7.4 capture does not list `hmac-secret-mc`. The tests
  count interface calls, not touches.
- **Fail closed.** A malformed answer from the key (wrong output count or
  length, more than 128 credentials) stops the unlock with
  `ErrAuthenticator`, even if the other factors alone would open the
  container. A misbehaving authenticator is not ignored silently.
- **A slot for the key alone is refused.** Its salt would have no partner to
  come from, so unlock could never ask for it.
- **Measured on the real key (2026-11-16, YubiKey 5, firmware 5.7.4, PIN
  mode, go-macos/fido `TestRealKeyDiscoverableNextAssertion`, go-authn/fido
  v0.8.0 `GetAssertions`):**
  - two discoverable credentials were announced (`numberOfCredentials` 2);
  - ONE verified request (one touch) returned both;
  - **both** assertions, the `getNextAssertion` one included, carried the
    `hmac-secret` output;
  - the next assertion's output equals a direct assertion of that credential.

  CTAP 2.1 §6.3 itself does not promise extension outputs on a next
  assertion (read 2026-11-16, partly through a summary). The behaviour is
  measured, not specified, so the adapter must treat a missing output as "this
  credential cannot be tried" and never as a key. **Still unknown:** a key
  with a display may let the person pick ONE credential instead (§6.2.2
  step 12), and other firmware may omit the outputs.

DESIGN.md §6.3 (pull request #1) still says the CTAP 2.1 `hmac-secret` section
was "not opened". This note opened it (§2.1). That row can be updated when
pull request #1 is next revised.

---

## 10. Not opened, and therefore unknown (not negative)

- CTAP 2.1 §6.4 definitions of the `uv`, `bioEnroll`, `uvBioEnroll`,
  `pinUvAuthToken` and `uvModality` options (the window read started at
  `alwaysUv`).
- The Bio's own `GetInfo`. go-authn/fido's
  `testdata/yubikey-fido-5.7.4-getinfo.hex` is from a YubiKey **5**, not a Bio:
  it has no `uv` or `bioEnroll` option. It shows `credProtect`, no
  `hmac-secret-mc`, `alwaysUv` false, `maxCredentialIdLength` 128 and
  `maxCredentialCountInList` 8. The same answers for a Bio need one capture
  (§7.2). That device also calls itself "YubiKey FIDO", so the product string
  does not identify a Bio (§4.1). The PID does.
- The format of Yubico credential IDs, and whether they are indistinguishable
  from random (§5.1, H2 (c)).
- Yubico's statement that a PIN must be set before a fingerprint can be
  enrolled (not found in the pages opened).
- OTP, OpenPGP and OATH on the Bio MPE (§4.1).
- `webauthn.dll`'s `hmac-secret` / PRF support and the API version that brought
  it (§6.4).
- pcscd's client socket protocol (pcsc-lite source), and purego's Linux
  support without cgo (§6.3).
- NIST SP 800-73-4 (PIV), for GENERAL AUTHENTICATE with RSA.
- How ZED! Enterprise wraps an archive key for an RSA user (SSTIC 2024 "Zed-Files"
  not opened for this, and no Enterprise sample) (§5.3).
- Yubico's PKCS#11 module (ykcs11) data-object support on the Bio (§5.2).
- Yubico's 5.7 firmware page
  (`docs.yubico.com/hardware/yubikey/yk-tech-manual/5.7-firmware-specifics.html`
  returned 404).
- The WebAuthn Level 3 rp id rules (§8.2).

## 11. Bibliography (opened)

1. FIDO Alliance, CTAP v2.1 PS with errata, 2022-06-21, §6.1.2–6.1.3, §6.2,
   §6.5.2.2, §6.5.3.1, §6.5.5.7.3, §6.5.6–6.5.7, §6.7, §11.2.4, §11.2.9, §12.1,
   §12.5.
2. FIDO Alliance, CTAP v2.2 PS, 2025-07-14, §12.7, §12.8.
3. systemd-cryptenroll(1), "FIDO2 Enrollment" and "Unlocking".
4. systemd `src/cryptenroll/cryptenroll-fido2.c` and
   `src/shared/libfido2-util.c`, branch `main`, 2026-11-15.
5. VeraCrypt documentation, "Security Tokens & Smart Cards" and "Keyfiles".
6. Yubico, YubiKey Technical Manual, "YubiKey Bio Series Specifics".
7. Yubico .NET SDK manual, "PIV PIN, touch and bio policies".
8. Yubico, ykman "PIV Commands".
9. Yubico, yubikit `piv` module source (API documentation).
10. go-piv/piv-go `v2`: `pcsc_unix.go`, `pcsc_windows.go`,
    `bio_integration_test.go`, README.
11. Fleet READMEs: go-authn/fido, go-authn/keyfactor, go-macos/fido,
    go-gnulinux/fido, go-gnulinux/factors, go-mswin/webauthn, go-fde/zed; and
    go-authn/fido `credential.go`, `clientpin.go` at v0.6.4.
