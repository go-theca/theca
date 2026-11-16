# Changelog

## Unreleased

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
