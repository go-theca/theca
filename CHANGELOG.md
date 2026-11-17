# Changelog

## Unreleased

- FIDO2 on Linux (go-gnulinux/fido v0.5.1, hidraw) and Windows
  (go-mswin/webauthn v0.5.0, `webauthn.dll`; Windows shows its own PIN dialog,
  `--pin-file` does not apply). The transport is chosen by `GOOS`. Not measured
  on a real key on either OS.

## v0.7.0

- Performance (#8, #9, #10). AES-256-CTR runs through `go-encryptions/ctr`
  (round keys expanded once, kernel call per sector, no allocation; `Zeroize`
  wipes the round keys), and Argon2id through `go-encryptions/argon2`, the
  `x/crypto/argon2` code with a NEON BLAMKA kernel on arm64: 1.54 to 0.73 of
  libsodium on an Apple M4 Max. Tables in `docs/perf-table.md`.
  AES-256-CTR is 1.03x and the sector tag 1.04x OpenSSL there (#8 and #9 stay
  open); Zen 4 was not re-measured.
- `TestKeyCommitment` no longer fails 1 run in 256 (it sealed a one-byte
  plaintext).

## v0.6.1

- go-filesystems/smb v0.16.1: per-source connection caps (32 per source, 16
  pre-auth; loopback is not exempt, and is far above one Finder client) and a
  zone-id fix.

## v0.6.0

- README: the `--network` live measurement (macOS 27.2.1).

- `Container.RemoveFactors(remove, keep)`, `SlotsOf`, `Slots`, `ErrLastWay`
  (#5): remove a slot by the factors that open it, and refuse, before any
  write, a removal that leaves the `keep` set with no other slot.
- `theca slots list|remove`.
- The metadata block cache and the Merkle node cache of an open container are
  bounded (#6): `OpenOptions.CacheBytes` / `CreateOptions.CacheBytes`, default
  64 MiB. Clean entries are evicted least-recently-used and wiped; dirty ones
  are pinned until commit; an evicted entry is authenticated again when read.
  `Close` wipes the caches.

## v0.5.0

- `serve --network` / `share.Options.Network`: serve beyond loopback, with
  message signing AND encryption required (of every session and of the share),
  never one without the other. Without it a non-loopback address is still
  refused, and the refusal names `--network`. A warning goes to standard error.
  With `--mount` and an unspecified address the local mount uses `127.0.0.1` on
  the same port.
- Breaking (below v1): `share.CheckAddr(addr, network bool)`; `Share.Addr()`
  added.
- go-filesystems/smb v0.15.0: replay window, session-hijack fix, connection and
  pre-auth bounds, `RequireSigning`, `EncryptData`.

## v0.4.1

- go-fileshare/automount v0.1.1 (go-freedesktop/gvfs v0.1.1): on Linux, when
  gvfs-fuse does not serve the session, `serve --mount` and `share.MountPath`
  no longer report `/` (the host's root) as the mount path; they report the
  share's URI. Measured live on Linux (Ubuntu 24.04, gvfs 1.54.4) and Windows
  11 by automount itself; not yet with theca.

## v0.4.0

- `share.Format(c)`: lays the exFAT filesystem onto a container's volume, through
  the container. `theca create --fs exfat` uses it, and so can any front end that
  creates containers (the GUI's Create does). A volume too small is refused.

## v0.3.0

- New package `github.com/go-theca/theca/share`: the logic of `serve` as a
  library, so a GUI can import it. `share.Start(ctx, c, Options{Addr, Name,
  Sync, Mount})` serves the exFAT inside an unlocked container over SMB on
  loopback and optionally mounts it; `URL`, `User`, `Password` (a secret),
  `MountPath`, `Done`/`Err` (a failed commit or server ends the share) and an
  idempotent `Stop` (unmount, close the server, close the filesystem; never the
  container). A container with no exFAT is refused with `share.ErrNoFilesystem`.
- `theca serve` is a thin front over it. Behaviour is unchanged, except that
  the address error now reads `address X: only a loopback address is served`
  and a failed mount no longer prints the `serving` line first.

## v0.2.0

- `create --fs exfat`: the volume is formatted through the container itself.
- `serve`: the exFAT inside is served over SMB on loopback, with one random
  account, committed every `--sync` and at stop.
- `serve --mount`: the share is mounted in the file manager (Finder, GNOME
  Files, Explorer) with no password dialog, through go-fileshare/automount, and
  unmounted at stop. `--credentials-out` is no longer required when `--mount`
  is given.
- go-filesystems/smb v0.13.0: SMB 3.1.1 (pre-authentication integrity,
  AES-GMAC signing) and encryption.

## v0.1.0

The first release. The format may still change before v1 (below v1, a
breaking change bumps the minor version).

- **Container format.**
  - Authenticated 4 KiB sectors: XChaCha20 xor AES-256-CTR, HMAC-SHA-256 tags.
  - A Merkle tree with sparse defaults and a write-ahead journal.
  - Two header copies.
  - No magic bytes: a container at rest looks random, except the tree area
    (DESIGN §19 I11).
- **Factors.**
  - A password (Argon2id), a 160-bit recovery code, and a FIDO2 key that is
    always paired with one of them.
  - Policies "any" (1 of 2) and "2of3".
  - A FIDO2 key holds a discoverable credential; its salt is derived from the
    partner factor (decision H2 revised, H7 relaxed: DESIGN §19 I21,
    HARDWARE-KEYS §9).
- **Integrity and recovery.**
  - Journaled commits.
  - A crash at any backing write leaves the old or the new content, never a
    mixture.
  - A rollback-counter protocol, tested against a software counter. There is
    no TPM counter yet: go-tpm2/tpm2#15.
- **CLI `theca`.**
  - Commands: create, info, verify, export, import, enroll-key, --fido2.
  - Secrets come from the terminal or from files that only their owner can
    read, never from arguments or the environment.
- **FIDO2 on macOS** (go-authn/fido v0.9.0, go-macos/fido v0.5.2), verified
  end to end on a YubiKey 5 with firmware 5.7.4.
- **Performance** against libsodium and OpenSSL, on one core, on an Apple M4
  Max and an AMD Zen 4 (docs/perf-table.md, docs/perf-zen4-table.md).
  - Faster than the C composition for a whole sector seal or open.
  - Slower on the AES-256-CTR and SHA-256 kernels and on arm64 Argon2id:
    #8, #9, #10.

Known limits, filed:
- #5: removing a slot by its factors.
- #6: bounded caches.
- #8, #9, #10: performance.
- No mounting, no FIDO2 on Linux or Windows yet.
