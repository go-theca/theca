# theca

Theca is an encrypted container format in pure Go. It has:

- authenticated sectors: XChaCha20 xor AES-256-CTR, with HMAC-SHA-256;
- a Merkle tree over the sector tags, and a write-ahead journal;
- no magic bytes;
- keyslots opened by a password (Argon2id), a recovery code, or both;
- an optional hardware rollback counter.

The design, its threat model, the primary sources it rests on and the
decisions taken are in [docs/DESIGN.md](docs/DESIGN.md). Hardware keys are
covered in [docs/HARDWARE-KEYS.md](docs/HARDWARE-KEYS.md).

Status: v0.1.0 released ([CHANGELOG](CHANGELOG.md)). Below v1 the format can
still change: a breaking change bumps the minor version.

## Command line

```sh
go install github.com/go-theca/theca/cmd/theca@latest

theca create vault.theca --size 1G            # asks the password twice, prints the recovery code once
theca info   vault.theca                      # unlock and describe
theca verify vault.theca                      # authenticate every sector and tree node
theca import vault.theca --password-file pw --offset 0 < disk.img
theca export vault.theca --password-file pw > disk.img
```

- **Secrets never go in arguments or environment variables.** The password is
  read from the terminal with echo off, or from `--password-file`. The recovery
  code is read from `--recovery-file`. Both files must be regular files that
  only their owner can read (mode `0600` or stricter); anything else is refused.
- `create` prints the recovery code once, on standard output. It is never
  stored. If you redirect it to a file, that file gets your umask (often
  `0644`): restrict it, or better, write the code down on paper.
- `--policy any` (the default): the password alone, or the recovery code
  alone, opens the container.
- `--policy 2of3`: two of the three factors are needed. Password and recovery
  code from the start; a FIDO2 key (`enroll-key`) then pairs with each.
- `import` reads its data from standard input, so it needs `--password-file`
  or `--recovery-file`. It is not one atomic transaction: on an error, the bytes
  written before the error are kept.
- Every command that opens a container states whether it is protected against
  rollback. In this version it never is: there is no hardware counter on the
  command line yet, so an older copy of a container would be accepted.

### FIDO2 security keys

```sh
theca enroll-key vault.theca --recovery-file rc   # pair the key with the password and the recovery code
theca info vault.theca --fido2                    # password + key
theca info vault.theca --recovery-file rc --fido2 # recovery code + key
```

- `enroll-key` makes ONE discoverable credential on the key: relying party
  `theca`, `credProtect` 3, `hmac-secret`. It pairs that credential with the
  password, and with the recovery code too when `--recovery-file` names it.
  The key is touched twice: to register, then to confirm.
- `--fido2` adds the attached key to an unlock. It pairs with the password
  or the recovery code. The key is never a factor alone.
- Nothing about the key is written into the container but its pairwise
  slots. The key is asked once per unlock, for all its Theca credentials (one
  touch).
- A key without a fingerprint asks for its PIN. It is read from `--pin-file`
  (mode `0600` or stricter) or from the terminal, never from an argument.
- macOS only for now (go-macos/fido). Tested on a YubiKey 5, firmware 5.7.4.

Design and trade-offs: [docs/HARDWARE-KEYS.md](docs/HARDWARE-KEYS.md) §9
"H2 revised", and [docs/DESIGN.md](docs/DESIGN.md) §19 I21.

Not in this version: mounting, FIDO2 on Linux and Windows, the TPM counter,
slot management on the command line (go-theca/theca#5).

## Library

```go
f, _ := os.OpenFile("vault.theca", os.O_RDWR, 0)
c, err := theca.Open(ctx, theca.FileBacking{File: f}, theca.Unlock{Password: pw}, theca.OpenOptions{})
// c is an io.ReaderAt and io.WriterAt over the logical volume; Sync commits.
```

## License

BSD-3-Clause.
