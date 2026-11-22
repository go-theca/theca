# Changelog

## Unreleased

- HMAC-SHA-256 now comes from `github.com/go-encryptions/hmac` v0.1.0 (byte-identical to
  `crypto/hmac`, RFC 4231 vectors unchanged) instead of the standard library, so the keyed inner and
  outer states can be wiped: `Keys.Zeroize` (called by `Close`) and a rebuild after a key change
  now wipe them. Tag comparisons use `crypto/subtle.ConstantTimeCompare`. Refs #74 item 4.

## v0.32.0

- The macOS lock/sleep detection moved out of theca: `internal/lockwatch`'s darwin half is now
  `github.com/go-macos/sessionwatch` (`Watch(ctx) (<-chan Event, error)`; `Lock`, `Sleep`,
  `Session`), usable by any macOS program. Behaviour is unchanged (notifications, proven by a probe,
  falling back to a 2 s poll); the log lines now start `sessionwatch:` instead of `close-on-lock:`.
  The Linux (logind) and Windows (session notifications) halves stay in `internal/lockwatch`.
  Still **not measured** on a real Mac: a real lock and a real sleep (go-theca/theca#59).
- `github.com/go-filesystems/smb` v0.17.1 -> v0.17.2: handles belong to their session and tree,
  and a FLUSH of an unknown handle returns `STATUS_FILE_CLOSED`.

## v0.30.0

- The TPM NV counter moved out of theca: `github.com/go-theca/theca/tpmcounter` is now
  `github.com/go-tpm2/nvcounter` (same API: `Options`, `Counter`, `Create`, `Open`, the `Err*`
  values, `First`, `Span`, `IDSize`, `DefaultLinuxDevice`, `TBSDevice`; error messages start
  `nvcounter:`). Nothing in it was theca-specific, and other go-tpm2 users can have it now.
  **Breaking for importers of `tpmcounter`** (the CLI is unchanged): change the import path.
  The two swtpm tests that mount a real container (rollback, identity pinning) stay here, in
  `cmd/theca/counter_swtpm_test.go`; the package's own swtpm and unit tests went with it.

## v0.31.0

- Memory pinning and the core-dump hardening now come from `github.com/go-authn/harden/memlock`
  v0.3.0 (the package moved out of `internal/memlock`; the mode policy stays in `internal/pin`).
  `--mlock` now has a Windows implementation: `VirtualLock`, where it used to do nothing. A refusal
  follows the same modes (`auto` says it once, `required` refuses to open, `off` skips).
- One `DisableDumps` for Linux and macOS (`RLIMIT_CORE` 0, plus `PR_SET_DUMPABLE` 0 on Linux and
  `PT_DENY_ATTACH` on macOS), tested in a child process.

## v0.29.0

- `--password-from`, `--recovery-from` and `--pin-from` accept `systemd-creds:NAME` (Linux), through
  go-authn/secretsource v0.8.0: a credential delivered in `$CREDENTIALS_DIRECTORY` by
  `LoadCredentialEncrypted=` / `LoadCredential=`, or decrypted from a `credstore.encrypted`
  directory. The bytes are taken exactly (seal with `printf %s`: a trailing newline would be part of
  the password). Measured on systemd 257 (Debian 13) with `--with-key=host`; not measured with a
  TPM2 key.
- README: a sample `theca serve` unit, and the PCR-binding trade-off (a bare `--tpm2-pcrs=7` can lock
  the vault after a firmware update; `host+tpm2`, a signed PCR policy, `systemd-pcrlock`,
  re-sealing).
- Test: every `-from` flag through the real secretsource with `systemd-creds:` (Linux).

## v0.28.0

### Windows sessions (go-theca/theca#58)

- `theca open`, `close` and `status` now work on Windows: a user-only named pipe whose client SID
  is checked, detach after the unlock, `LockFileEx` on the container, and a message-only window
  that closes the session on lock, logoff and suspend. The daemon leaves the OpenSSH job
  (`CREATE_BREAKAWAY_FROM_JOB` when the job allows it) so it survives the logout, and the profile
  file is checked by its DACL instead of a POSIX mode. README and DESIGN I26 say what was and was
  not measured.

### Tests (go-theca/theca#76)

- Test-only: the mutsweep survivors and hangs in `theca.go` are killed (delete mode: 14 survivors
  and 2 hangs before, 0 and 0 after) and a runaway mutant is caught in seconds by a 10 s deadline.

### Security

- Fewer secret copies (go-theca/theca#74). BREAKING for library callers: `theca.Create` and
  `format.NewRecoveryCode` return the printed recovery code as `[]byte` (the caller wipes it),
  not `string`; `create` writes it to the terminal from the bytes and clears it.
- The PIN reaches the key through go-authn/fido v0.15.0 `PINTokenBytes`: no immutable `string`
  of the PIN is made any more (the one copy v0.25.0 documented is gone).
- go-authn/secretsource v0.7.0: on Windows a `file:` secret is now checked against its DACL
  (see that release's notes for the exact rule).
- Documented, not fixed: the AES round keys are wiped by `Close` through `ctr.Cipher.Zeroize`
  only on go-encryptions/ctr's accelerated path (the `crypto/aes` fallback's schedule cannot be
  cleared), stack copies of by-value KEKs, and `crypto/hmac`'s internal pads. A local wiping HMAC
  was not adopted: it was not measured against the standard library (load ~29).

## v0.27.0

- `theca journal resize FILE --out NEW` (go-theca/theca#73): a container made before v0.26.1 has a
  journal of 64 entries and writes at about 12 MiB/s; the journal size is part of the layout, so
  it could not change. `resize` writes NEW, a copy with the default journal for the volume (or
  `--entries N`), through `theca.Resize`. Why a copy and not an in-place rewrite: the journal sits
  before the metadata, the tree and the data, so a new size moves every area after it, and an
  in-place move has a crash window in which neither layout is whole. A copy has none: FILE is
  never rewritten, NEW is created with `O_EXCL` and synced, then reopened, checked sector by
  sector and compared with FILE by the SHA-256 of the volume, and only then reported. The swap is
  printed, never run. Key slots, the counter binding (handle, name, TPM identity, derived
  authValue) and the content are carried over; the sectors are copied as they are (a sector is
  sealed under the container id and its index, not its offset) and the header is sealed again.
  The container has no hidden volume (DESIGN section 8 is a verdict, not a feature), so the area
  the copy leaves out is only random padding.
- Rollback counter: opening FILE is an ordinary mount and moves the counter once. The check of
  NEW is done with the counter's increment swallowed, so it does not move it again; NEW's first
  real mount finishes that increment and moves the counter past FILE, which is refused as a
  rollback from then on. Until then FILE still opens: keep it until NEW has been mounted once.
- go-filesystems/smb v0.17.1: the first write of exactly 64 KiB on a handle is served (smb#70,
  the credit check counted the fixed part of the WRITE request). `TestFirstWriteOf64KiB` fails on
  v0.16.1 and passes on v0.17.1.
- Tests: the copy is cut at every write and every sync, and failed once at every write, sync and
  read, on both files; the error returned is the one that failed and FILE is byte for byte as it
  was. `internal/synccost`: `TestResizeShareCost` (`THECA_SHARE_RESIZE`).

## v0.26.1

- Sustained writes are 4 to 8 times faster on a new container (go-theca/theca#73). The issue
  blamed one commit per 4 KiB sector; the code already batches (`WriteAt` commits only when the
  journal is full, DESIGN I12), and the 0.7 MiB/s was a journal of 8 entries. Every commit costs
  about four flushes whatever its size, so the journal size is the batch size. `create` now sizes
  the journal at one entry per 16 sectors, clamped to 64..4096 (`theca.DefaultJournal`), instead
  of always 64. On macOS, 64 MiB through `Container.WriteAt`: 12.0 to 92.4 MiB/s; through the SMB
  share: 7.6 to 28.8 MiB/s. No format change: the journal size was already a header field, and an
  existing container keeps its own (64 entries by default: about 12 MiB/s).
- Tests: a `WriteAt` larger than the journal, cut at every backing write and with every flush
  failing in turn, reopens whole (each sector old or new, new ones a prefix, tags and tree verify).
- `internal/synccost`: the measurement (`THECA_SYNC_COST`, `THECA_SHARE_COST`).

## v0.26.0

- The TPM counter works on Windows (go-theca/theca#37): `--tpm-device` defaults to `tbs:`
  there, TPM Base Services through go-tpm2/devtpm v0.4.0 (`OpenTBS`, pure Go). Naming `tbs:`
  elsewhere is refused as unsupported. Measured on a Windows 11 ARM64 VM without a TPM: the
  real `tbs.dll` answers `TBS_E_TPM_NOT_FOUND`. A counter through a real Windows TPM has not
  been run.

## v0.25.0

### Security

- Key memory hardening (go-theca/theca#68).
  - The PIN and the recovery code are `[]byte` end to end and cleared after use, like the
    password. BREAKING for library callers: `Unlock.Recovery` is `[]byte`,
    `RecoveryFactor` and `format.ParseRecoveryCode` take `[]byte`, and the `fido2` PIN
    callbacks return `[]byte` (the callee wipes it). One `string` copy remains at the
    go-authn/fido `PINToken` call.
  - The pages holding the master secret, the slot wrap keys and their caches are `mlock`ed
    (new `internal/memlock`, per-page counts). `--mlock=auto` (default) reports a refusal
    once; `--mlock=required` makes it an error; `--mlock=off` disables it. The daemon gets
    the mode of the `open` that started it.
  - `theca _serve` sets `RLIMIT_CORE` to 0 and `PR_SET_DUMPABLE` to 0 (Linux), or
    `RLIMIT_CORE` to 0 and `PT_DENY_ATTACH` (macOS). A refusal is a warning.

## v0.24.0

### Security

- A counter asked for is a counter required (go-theca/theca#66). A container made without
  a counter and bound later by `counter rebind` left every earlier copy with a header naming
  no counter; restored over the file, such a copy opened under `--counter tpm` (exit 0, only
  a note) and the TPM was never consulted. `theca.Open` now refuses with the new
  `ErrCounterRequired` when `Counter`, `CounterFor` or `CounterDerived` is given and the
  header names none, and the command line says: "this container has no rollback counter, but
  --counter tpm was asked: an older copy may have been restored". With no counter asked, a
  container with none still opens (with the note). BEHAVIOUR CHANGE: a caller that handed a
  counter to a counter-less container used to have it ignored.
- `close-on-lock` fails closed: if the lock watcher cannot start, `open` closes the container
  again and fails, naming `--close-on-lock=false` as the explicit opt-out, instead of leaving
  it mounted with a warning.
- Linux lock watcher: only logind's signals count (sender `org.freedesktop.login1`, matched on
  the bus and checked on the signal) and only for this process's own session (found by
  `GetSessionByPID`, else `XDG_SESSION_ID`); the session's `LockedHint` is read at start, so an
  already-locked session closes at once. A locker that sets nothing in logind is not seen (see
  the README).
- `profile.Validate` bounds every written line to `MaxLineBytes`, so `Add` refuses what
  `Parse` would refuse later (a profile that made the whole file unreadable).
- The loopback SMB share requires message signing (it was only offered); the README said
  "signed".

## v0.23.0

- `session.Start(ctx, exe, name, notice)` (go-theca/gui#12): the spawn of the background
  process of `theca open` moves from `cmd/theca` into the importable `session` package, so a
  program other than the command line (the GUI) opens a profile with the same code. The process
  has no terminal; each line it writes to standard error while it unlocks (the key's "touch"
  notice) reaches `notice`, in order, until `Start` returns. `session.StartAttached` is the
  terminal form that `theca open` uses; its behaviour is unchanged.

## v0.22.0

- macOS `close-on-lock` is event-driven (go-theca/theca#59): `com.apple.screenIsLocked`
  (NSDistributedNotificationCenter), `NSWorkspaceWillSleepNotification` (the container is
  closed BEFORE the sleep, not after the wake) and `NSWorkspaceSessionDidResignActiveNotification`,
  through go-macos/objc v0.13.0 (`Observe`, `Post`, `RunMainLoop`). No polling lag.
- These notifications are delivered on the main thread's run loop only (measured), so the
  background process pins its main goroutine to the main thread and runs the loop there while
  the container is served on other goroutines.
- The observers are proven at start: the process posts a notification of its own name and
  waits for it. If they cannot be registered, or nothing delivers them, it falls back to the
  2 s poll of `CGSSessionScreenIsLocked` and the clock-jump check. `theca open` prints which
  mode is active on standard error.

## v0.21.1

- The command that `enroll-key` prints (what still opens the container) and the "needs the
  password / recovery code: give ..." refusals now name `--password-from REF` /
  `--recovery-from REF`, never a deprecated `-file` flag; a short note says what REF is. The
  messages of `import`, `--require` and the terminal-less refusal, and the `slots` help, do the same.

## v0.21.0

- Deprecated: `--password-file`, `--recovery-file`, `--pin-file`, `--tpm-auth-file`,
  `--tpm-owner-auth-file` (go-theca/theca#55). They still work, are hidden from the help, and
  each use prints a warning on standard error naming the `--X-from` replacement. So does a
  `file:` reference in `--password-from`, `--recovery-from` and `--pin-from`. Removal is a
  later MINOR release (below v1.0.0 a breaking change is a MINOR bump); the TPM flags go
  first, the three container-secret flags after a separate decision.
- Breaking: `--tpm-auth-from` refuses a `file:` reference, as `--tpm-owner-auth-from` and
  `--tpm-endorsement-auth-from` already did. (Use `--tpm-auth-file`, or a secret manager.)
- The `--password-from` family help no longer lists `file:PATH` as a choice.

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
