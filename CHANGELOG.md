# Changelog

## v0.20.0

- Multi-factor made easy every day: `theca profile add NAME FILE ...` names a container once,
  `theca open NAME` unlocks it (the password from the secret manager, one touch of the key),
  mounts it in the file manager and frees the terminal, `theca close NAME` unmounts, commits
  and closes it, `theca status` says what is open.
- Profiles are in `containers.toml` under `os.UserConfigDir()/theca` (mode 0600, directory
  0700) and hold only references: the container path, `password-from` / `recovery-from` /
  `pin-from` (keychain:, secretservice:, keepassxc:; `file:` refused), `device`, `counter`,
  `tpm-device`, `tpm-auth-from`, `tpm-endorsement-auth-from`, `share`, `sync`,
  `close-on-lock`. `profile add` checks the references' syntax and never reads a secret.
  A file another user can read is refused. The parser is bounded and fuzzed (`FuzzParse`).
- The background process holds the unlocked container; `close` and `status` reach it over a
  Unix socket (mode 0600, in a 0700 directory under `$XDG_RUNTIME_DIR/theca` or
  `os.UserConfigDir()/theca/run`) that checks the peer's user ID (SO_PEERCRED, LOCAL_PEERCRED).
  A message is one JSON line of at most 4096 bytes; the decoder is fuzzed
  (`FuzzDecodeRequest`). No secret crosses it. The container file is locked for the life of
  the process: a second `open` is refused before any unlock or counter increment.
- `close-on-lock` (default true) closes the container when the screen locks, the machine
  sleeps or the session ends: Linux asks logind over D-Bus (`Lock`, `LockedHint`,
  `PrepareForSleep`, `PrepareForShutdown`); macOS reads `CGSSessionScreenIsLocked` every 2 s
  and detects a sleep as a wall-clock jump the monotonic clock did not make. Windows has
  neither yet: the container stays open until `close`.
- New packages `profile` and `session` (the same API a GUI uses).

## v0.19.0

- A TPM with an endorsement hierarchy password no longer locks its owner out of a pinned
  container (follow-up to go-theca/theca#39): `--tpm-endorsement-auth-from REF` gives the
  password at `create`, `counter rebind` and every mount. A TPM refusal is reported as such
  and names the flag. A wrong password does not count toward the TPM's dictionary-attack
  lockout (TCG Part 1 rev 1.59, 19.8.1; measured on swtpm).
- The counter's authValue is derived from the container's master key (HKDF-SHA-256, DESIGN
  5.4.2) when `create --counter tpm` gets no `--tpm-auth-*` flag: no password file beside the
  hardware keys. The header records it (flag bit 2); mounts need no counter flag. Counters
  made by older versions keep working with their flag; `theca counter rebind` without
  `--tpm-auth-*` migrates a container to a derived authValue.
- New: `--tpm-owner-auth-from`, `--tpm-auth-from` (secret managers). A `file:` reference is
  refused for `--tpm-endorsement-auth-from` and `--tpm-owner-auth-from`. `--tpm-auth-file`
  and `--tpm-owner-auth-file` still work and are marked deprecated in the help.
- `info` prints where the counter's authValue comes from.
- Library: `CreateOptions.NewCounter`, `OpenOptions.CounterDerived`, `OpenOptions.RebindDerived`,
  `Info.CounterDerivedAuth`, `tpmcounter.Options.EndorsementAuth`, `tpmcounter.ErrEndorsementAuth`.
  Needs go-tpm2/tpm2 v0.12.0. Header format: one more optional flag bit; older readers
  refuse a header that has it.

## v0.18.0

- The rollback counter is pinned to THIS TPM (go-theca/theca#39). `create` and
  `counter rebind` record the identity of the TPM (the digest of the Name of its ECC P-256
  endorsement key, created transiently and flushed) in the authenticated header; every
  mount checks it before it reads the counter, and a counter on another TPM is refused,
  naming both identities and the recovery. Before, another TPM with the same index, the
  same Name and a value raised to an old bound accepted an old copy (reproduced on two
  swtpm instances; fixed).
- Containers made by older versions carry no identity: they open as before, with a warning
  at every mount and on `info`, until `theca counter rebind` pins them.
- Not stopped, and stated in the README: whoever controls the TPM in use, or holds a copy of
  its state, or forges the bus answers. `TPM2_NV_Certify` was weighed and deferred
  (DESIGN 5.4.1).
- Library: `IdentifiedCounter`, `ErrCounterIdentity`, `ShortID`, `Info.CounterTPM`,
  `tpmcounter.Counter.Identity`. Needs go-tpm2/tpm2 v0.11.0. Header format: one optional
  field (flag bit 1); older readers refuse a header that has it, newer readers read older ones.

## v0.17.1

- Fix: the help showed `--device fido list` — pflag takes the first backquoted text of a
  usage string as the value name. It reads `--device ID` again (an id or a key name), and a
  test walks every flag of every command and refuses a value name that is not one word.

## v0.17.0

- `enroll-key` says, after pairing, which factors still open the container alone (the
  password; the recovery code when presented; a recovery code not presented is not tested
  and the output says so) and prints the exact `slots remove` command that removes the
  password-only slot (go-theca/theca#43).
- `slots remove --remove SET --keep SET` accepts sets with the key: `password+fido2`,
  `recovery+fido2` (any order; the key opens a slot only with one partner). A set with the
  key is verified before anything is written: ONE touch on the key, and the slot it opens
  must exist and must not be among the removed ones, else `ErrLastWay`. `slots remove` and
  `slots list` take `--fido2`, `--device`, `--pin-file` and `--pin-from`.
- `enroll-key --require`: pair, prove with one more touch that the password with the key
  opens the container, then remove the password-only slot. The recovery code alone is NOT
  removed (it is the way in if the key is lost); the output says so, with the command.
- Library: `RemoveFactorSets(remove, keep [][]Factor)` (`RemoveFactors` is its one-set
  case), `KeyPairs(ctx, dev, partners...)`, `WipeSets`.
- Compatible: every `--remove` / `--keep` value accepted before still is. The error for an
  unknown set now lists the five sets.

## v0.16.0

- `create --password-to REF`, `--recovery-to REF`, `--generate N`, `--replace`: the new
  password and the recovery code go straight into a secret manager
  (`keychain:`, `secretservice:`, `keepassxc:URL`) through go-authn/secretsource v0.5.0,
  so neither is typed into a file or left on the terminal. `--generate N` draws the password
  (letters and digits) and needs `--password-to`; `--password-to` and `--generate` exclude
  `--password-file` and `--password-from`.
- Order, so a failure is safe: the password is stored BEFORE the container is created (a
  failed store creates nothing; a later failure says the password stays stored, for no
  container). The recovery code is stored after creation, and when that store fails it is
  printed after all (the only copy) and create exits with the error.

## v0.15.0

- Fix: `--*-from keepassxc:by-uuid/...` and `keepassxc:by-path/...` (v0.14.0)
  crashed KeePassXC 2.8.0 when the entry had no URL. They are refused now;
  `keepassxc:URL` (the entry's URL field) is the form. go-authn/secretsource v0.3.0.

## v0.14.0

- `--password-from`, `--recovery-from` and `--pin-from` also take
  `keepassxc:by-uuid/HEX`, `keepassxc:by-path/Group/Title` and `keepassxc:URL`
  (KeePassXC's browser-integration protocol; macOS and Linux, one association
  approved in KeePassXC with `secretsource keepassxc associate`) and
  `secretservice:KEY=VALUE[,...]`, through github.com/go-authn/secretsource v0.2.0.

## v0.13.0

- FIDO2: a key can be named, and `--device` takes the name. A name stored ON the
  key (`fido name set NAME` from go-authn/fido `cmd/fido` v0.4.0; go-authn/fido
  v0.12.0) is read with no touch and no PIN, so `--device NAME` finds the key
  wherever it is plugged, and the key is shown by its name when theca names it
  (`Using security key: ... "desk key"`, and in `enroll-key`'s `ok:` line). A
  name must be on exactly one key; on two, theca refuses and names both. A key
  that will not answer the silent read has no name here and is chosen by its
  `--device` id. Not run against a real key.

## v0.12.0

- Secrets from a secret manager instead of a plaintext file: `--password-from`,
  `--recovery-from` and `--pin-from` on every command that took the matching
  `-file` flag. The value is a reference (`keychain:SERVICE/ACCOUNT`,
  `secretservice:SERVICE/ACCOUNT`, `file:PATH`) resolved by
  github.com/go-authn/secretsource v0.1.0; there is no scheme that runs a
  command. Each is exclusive with its `-file` flag, which is unchanged (and now
  shares the same reader). `create --password-from` does not ask the password
  twice. The terminal-less error and the `import` hint name the new flags.

## v0.11.0

- FIDO2: choose the key. With several keys attached theca took whichever the
  transport listed first, which can be the wrong key to enrol on. `--device ID`
  on `enroll-key` and every `--fido2` command names one (macOS
  `iokit:<location>`, Linux the USB port); with several attached and none named,
  the person touches the one to use (go-authn/fido v0.11.0 `Select`), two keys
  touched together are refused, and the key is named before anything is asked of
  it. `enroll-key` prints which key it paired. `fido2.WithDevice`,
  `fido2.Device.Label`, `fido2.ErrNoKey`. Windows chooses in its own dialog and
  refuses `--device`. go-macos/fido v0.6.0, go-gnulinux/fido v0.6.0. Tested with
  answering fake keys; not run against two real keys.

## v0.10.3

- FIDO2: a key whose fingerprint fails falls back to its PIN. Built-in
  verification is used only when GetInfo says `uv` is true (CTAP 2.1 6.4); on
  CTAP2_ERR_UV_INVALID the tries left are read (getUVRetries) and shown, and on
  UV_BLOCKED, no tries left, or no fingerprint enrolled (NOT_ALLOWED) theca says
  so and uses the PIN when one is set (6.5.5.7.3 note), else `ErrUVLocked`.
  Not measured on a real YubiKey Bio.

## v0.10.2

- **Fix: a second mount in the same macOS session failed** ("authentication
  error (errno 80)") because every share used the account name `theca`, and
  macOS replays a stale credential for a fixed account name on 127.0.0.1. The
  server received an NTLMv2 proof that matched no password it had served. Each
  share now draws its own account name, `theca-` and 8 random base32
  characters (`share.UserPrefix`, `Share.User()`); `theca serve` writes it in
  `--credentials-out`. Before the fix a fixed name failed 12 of 12 repeats;
  with a random name 0 of 120 (smb author's harness). A live regression test
  (`THECA_SHARE_LIVE=1`) mounts a network share ten times in one process.
- Breaking (below v1): the `share.User` constant is gone; use `Share.User()`.

## v0.10.1

- `counter rebind` deletes the old counter when it is still there (with the
  owner password it already holds), before binding the new one. Before, a
  healthy old counter stayed at its value, so a copy of the container taken
  just before the rebind (old handle, bound equal to that value) opened with no
  flag: a silent rollback to before the rebind. The warning says whether the
  old counter was deleted or already absent. If it cannot be checked or
  deleted, nothing is made and the rebind stops. swtpm test: a pre-rebind copy
  is refused.
- The recovery hint says an old copy of the container shows the same message
  as a reset TPM, and that rebinding is not the way to open an old copy.

## v0.10.0

From the independent review of v0.9.0.

- `theca counter rebind FILE --counter tpm`: when the counter is gone (the
  index undefined, `TPM2_Clear`, a reinstall) the container could not be opened
  at all, and the README said `--accept-rollback` would help; it needs a
  counter to compare. The refusal now names the recovery. `rebind` needs the
  unlocking factors and the owner password, defines a counter (at the recorded
  handle if free), binds the header to it and increments. Rollback protection
  restarts from that moment. Library: `OpenOptions.RebindFor`,
  `tpmcounter.ErrNoCounter`. Tested on swtpm for a deleted index and for a
  replaced TPM.
- New counters carry `TPMA_NV_NO_DA` (go-tpm2/tpm2 v0.10.0): a wrong authValue
  file no longer counts towards the TPM's lockout. Counters made by v0.9.0 are
  still opened.
- `share.Start` reads `serveSMB` before starting its goroutine: a data race
  (found on arm64 CI in `TestShareEndsOnAFailure`, twice in a row on this PR)
  between that goroutine and a test restoring the variable.
- Documented the limit that the header binds a counter's handle and Name, not
  a TPM (DESIGN §19 I22, README threat model).

## v0.9.0

- TPM rollback counter. `theca create --counter tpm` defines a TPM 2.0 NV
  counter (go-tpm2/tpm2 v0.9.0) and binds the container to it; every command
  that opens the container takes `--counter tpm` and refuses an older copy
  (DESIGN §5.4: checked before journal replay, incremented once per mount).
  `info` says protected or not and names the NV index. New package
  `tpmcounter`; `OpenOptions.CounterFor` finds the counter from the
  authenticated header; `Info.CounterHandle`; flags `--tpm-device`,
  `--tpm-handle`, `--tpm-auth-file`, `--tpm-owner-auth-file`,
  `--accept-rollback`. Linux `/dev/tpmrm0` or a software TPM
  (`unix:SOCKET`); macOS and Windows say there is no TPM interface.
- A mount under a counter rebinds the header, so `info`, `verify` and
  `export` open the file read-write when `--counter tpm` is given.
- The NV Name changes once, at the first increment (it covers TPMA_NV_WRITTEN):
  the counter reads its Name again after an increment. Found by the
  swtpm-backed test.
- DESIGN §19 I22: `POLICY_DELETE` cannot be used on an owner-defined index
  (it needs platform authorization), so the owner can delete the counter:
  a denial of service, never a rollback.

## v0.8.0

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
