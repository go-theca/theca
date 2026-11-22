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

## Quick start: one command, one touch

Password from your secret manager plus a hardware key, with nothing new stored:

```sh
go install github.com/go-theca/theca/cmd/theca@latest

# once: name the container (references only, nothing secret is written)
theca profile add vault ~/vault/vault.theca \
    --password-from 'keepassxc:https://theca.invalid/vault' --device bio

# every day
theca open vault      # asks the manager, waits for one touch, mounts, frees the terminal
theca status          # what is open, where
theca close vault     # unmounts, commits, closes
```

`profile add` checks the syntax of the references and never reads a secret.
The profile file (`containers.toml`, mode 0600, in the user's configuration
directory) holds the container's path, `--password-from` / `--recovery-from` /
`--pin-from` references (`keychain:`, `secretservice:`, `keepassxc:`; `file:` is
refused), `--device`, `--counter tpm` with `--tpm-device`, `--tpm-auth-from`,
`--tpm-endorsement-auth-from`, `--share`, `--sync` and `--close-on-lock`. A
counter whose authValue is derived from the master key (the default since
v0.19.0) needs no `--tpm-auth-from`; `--counter tpm` stays in the profile, since
the header can be read only after the unlock.

`open` starts a background process that holds the unlocked container; `close`
and `status` talk to it over a per-user Unix socket (mode 0600, peer user ID
checked). A second `open` of the same container is refused. With
`--close-on-lock` (the default) the container is closed when the screen locks,
the machine sleeps or the session ends: logind over D-Bus on Linux, the
screen-lock, will-sleep and session-resign notifications on macOS (delivered
before the sleep, no polling; `theca open` says on standard error whether it
listens or, if the notifications cannot be heard, polls every 2 s). Windows has no
auto-close yet. On Linux only logind's own signals about this process's own
session count (sender `org.freedesktop.login1`, the session of this process's
pid or `XDG_SESSION_ID`), and a session that is already locked at `open` closes
at once. If the watcher cannot start (no logind, no session), `open` fails and
nothing stays mounted: `--close-on-lock=false` is the explicit opt-out. Limit:
a screen locker that tells logind nothing (a bare `i3lock` or `swaylock` that
neither calls `loginctl lock-session` nor sets the session's `LockedHint`) is
not seen; the container then closes on sleep, shutdown or `theca close`, not on
that lock. `profile list` and `profile remove NAME` list and delete
profiles (the container and the manager's entries stay).

## Command line

```sh
go install github.com/go-theca/theca/cmd/theca@latest

theca create vault.theca --size 1G            # asks the password twice, prints the recovery code once
theca info   vault.theca                      # unlock and describe
theca verify vault.theca                      # authenticate every sector and tree node
theca import vault.theca --password-from keychain:theca/vault --offset 0 < disk.img
theca export vault.theca --password-from keychain:theca/vault > disk.img
```

- **Secrets never go in arguments or environment variables.** The password is
  read from the terminal with echo off, or from a secret manager (next item).
- **Secret files are deprecated (v0.21.0).** `--password-file`, `--recovery-file`,
  `--pin-file`, `--tpm-auth-file` and `--tpm-owner-auth-file` still work (a regular
  file, mode `0600` or stricter) but are hidden from the help, and each use prints
  a warning on standard error that names the `--X-from` replacement. So does a
  `file:` reference in `--password-from`, `--recovery-from` and `--pin-from`.
  `--tpm-auth-from` refuses `file:`, like the other TPM flags. A plaintext file
  beside a container protected by hardware keys defeats them. Scripts keep
  working; move them to a manager before the files are removed.
- **From a secret manager, so no plaintext file sits on disk.**
  `--password-from`, `--recovery-from` and `--pin-from` (the FIDO2 key's PIN) take
  a reference: `keychain:SERVICE/ACCOUNT` (macOS Keychain),
  `secretservice:SERVICE/ACCOUNT` or `secretservice:KEY=VALUE,...` (GNOME
  Keyring, KWallet, KeePassXC with *Secret Service Integration*),
  `keepassxc:URL` (KeePassXC itself, on macOS and Linux, through its
  browser-integration socket; the reference is the URL field of the entry: enable
  it, run `secretsource keepassxc associate` once and approve it in KeePassXC.
  Lookups by UUID or path are refused: KeePassXC 2.8.0 crashes on an entry without
  a URL); `file:PATH` still works there but is deprecated. A reference holds no secret, and
  no scheme runs a command. Each excludes the `-file` flag of the same secret.
  See [go-authn/secretsource](https://github.com/go-authn/secretsource).

  ```sh
  security add-generic-password -s theca -a vault -w          # macOS: asks for the password
  theca info vault.theca --password-from keychain:theca/vault
  theca info vault.theca --fido2 --password-from secretservice:theca/vault --pin-from secretservice:fido/yubikey-5c
  theca info vault.theca --fido2 --password-from 'keepassxc:https://theca.invalid/vault' --pin-from 'keepassxc:https://fido.invalid/yubikey-5c'
  ```
- `create --password-to REF [--generate 24] [--recovery-to REF2] [--replace]` stores the new
  password (typed twice, or drawn) and the recovery code in a secret manager, with no plaintext
  file and nothing secret printed. The password is stored before the container is created; if
  storing the recovery code fails, the code is printed after all. For example:

  ```sh
  theca create vault.theca --size 1G --password-to 'keepassxc:https://theca.invalid/vault' --generate 24 \
      --recovery-to 'keepassxc:https://theca.invalid/vault-recovery'
  ```

- `create` prints the recovery code once, on standard output. It is never
  stored. If you redirect it to a file, that file gets your umask (often
  `0644`): restrict it, or better, write the code down on paper.
- `--policy any` (the default): the password alone, or the recovery code
  alone, opens the container.
- `--policy 2of3`: two of the three factors are needed. Password and recovery
  code from the start; a FIDO2 key (`enroll-key`) then pairs with each.
- `import` reads its data from standard input, so it needs `--password-file`,
  `--password-from`, `--recovery-file` or `--recovery-from`. It is not one atomic transaction: on an error, the bytes
  written before the error are kept.
- Every command that opens a container states whether it is protected against
  rollback. Without `--counter tpm` it is not: an older copy of the container
  would be accepted (see "Rollback counter" below).

### Keyslots

```sh
theca slots list   vault.theca --password-file pw --recovery-file rc
theca slots remove vault.theca --password-file pw --recovery-file rc --remove recovery --keep password
```

- A keyslot holds nothing that says what opens it, so `list` shows the recorded
  slots and which ones the factors **you present** open.
- `remove` takes the slot(s) a factor set opens (`password`, `recovery`,
  `password+recovery`, `password+fido2` or `recovery+fido2`) and a DIFFERENT set
  to `--keep`, which must still open the
  container: this is checked before anything is written, and a removal that
  would leave no way in is refused. Both sets are presented with
  `--password-file` / `--recovery-file` (or the terminal).
- A set with the key touches it ONCE (`--device`, `--pin-file` as for
  `--fido2`): the slot it opens must exist and must not be among the removed
  ones, so a key that is not the one enrolled here, or that holds no Theca
  credential, is refused before any write. To make the key mandatory:
  `theca slots remove vault.theca --password-file pw --remove password --keep password+fido2`.
  A container only the key opens also needs `--fido2` to be opened (a second touch).
- It stops access to **this copy** only: anyone holding an older copy can still
  open it with the removed factor (DESIGN §2, R7).
- Library: `Container.RemoveFactors(remove, keep []Factor)`,
  `RemoveFactorSets(remove, keep [][]Factor)`, `KeyPairs`, `SlotsOf`, `Slots`,
  `ErrLastWay`.

### Serving the files inside: SMB on loopback

```sh
theca create vault.theca --size 4G --fs exfat      # a container holding an exFAT filesystem
theca serve vault.theca --mount                    # appears in the Finder; Ctrl-C unmounts and stops
# serving smb://127.0.0.1:58738/theca; Ctrl-C to stop
# mounted at /Volumes/theca
theca serve vault.theca --credentials-out creds.json   # or: hand the account to another client
```

- `create --fs exfat` formats the volume through the container itself
  (go-filesystems/exfat `FormatImage`). No decrypted copy is ever written to
  disk.
- `serve` unlocks the container and serves its exFAT over SMB (2.1 to 3.1.1,
  signed) using go-filesystems/smb. The server REQUIRES message signing on
  loopback too (`RequireSigning`), not only beyond it: a session that does not
  sign is refused.
  - It listens on a **loopback address only** by default: the data is
    decrypted. See "Beyond loopback" below.
  - One random account is drawn per run (a random user name, `theca-` and 8
    characters, as well as a random password), never printed or passed as an
    argument. The name is random on purpose: macOS replays a stale credential
    for a fixed name on 127.0.0.1 and fails the next mount.
  - `--mount` mounts the share in the file manager with **no password
    dialog** (go-fileshare/automount): the password goes to the OS mount
    service as a value. At stop it unmounts first, so the client flushes
    through the server, then commits and closes the container.
  - `--credentials-out` writes the URL, user and password to a file (mode
    `0600`, created only if absent, removed at exit), for another client.
    One of the two is required.
  - Writes are committed to the container every `--sync` (default 5 s) and
    when the server stops.
- Measured on macOS 27 (2026-11-16): `--mount` lands in `/Volumes/theca` over
  SMB 3.1.1 signed with AES-128-GMAC, a file written through it survives a
  stop and a remount, and `verify` passes. Linux (GNOME Files, through gvfs)
  and Windows (Explorer, a drive letter through `MSFT_SmbMapping`) use the
  same command; neither has been measured with theca yet.
- A copy of a file written through the share is one transaction per journal
  budget, not one per file (DESIGN §19 I12). A crash in the middle of a large
  copy can leave the exFAT metadata of that copy half-written, as on a disk.
- The journal budget is the batch: every commit costs about four flushes
  (`F_FULLFSYNC` on macOS) whatever its size. `create` sizes the journal at one
  entry per 16 sectors, from 64 to 4096 (`--journal` overrides), so a 64 MiB
  sustained write through the share went from 7.6 to 28.8 MiB/s on macOS
  (go-theca/theca#73). The size is part of the layout, so it cannot change in
  place: a container made before v0.26.1 keeps its 64 entries until you copy it
  with `theca journal resize` (below).

#### Resizing the journal of an existing container

```sh
theca journal resize vault.theca --out vault-new.theca --password-from keychain:theca/vault --device bio   # the factors that open it
```

`resize` writes `vault-new.theca`, a copy whose journal has the default size for
the volume (or `--entries N`). Keys, slots, the policy, the rollback counter
binding and the content are carried over. The copy is created exclusively (an
existing `--out` is refused), synced, reopened, verified sector by sector and
compared with the original by the hash of the whole volume; nothing is reported
before that passes. `vault.theca` is never rewritten (opening it is an ordinary
mount, and that is all), and nothing is swapped for you: the command prints the
two `mv` lines to run. With a TPM counter, the first real mount of the copy moves
the counter past the old file, which is refused as a rollback from then on, so
keep it until the copy has been mounted once. Containers have no hidden volume
(DESIGN section 8), so there is nothing in the file that the copy leaves behind.

#### Beyond loopback: `--network`

```sh
theca serve vault.theca --network --addr 0.0.0.0:4455 --mount --credentials-out creds.json
```

A non-loopback `--addr` is refused unless `--network` is given (the library:
`share.Options{Network: true}`). It is one switch, not a knob per protection:
the server is then started with **message signing required, encryption required
of every session, and encryption required of the share**
(go-filesystems/smb v0.15.0 `RequireSigning`, `EncryptData`, `RequireEncryption`),
and a client that cannot do both (SMB 2.1, or one that refuses encryption) is
refused. That is the only condition under which three independent security
reviews found serving beyond loopback acceptable. It does not make it safe for
a hostile network: anyone who can reach the address and has the password can
read and write the container's files, and the password is in `--credentials-out`.
`serve` prints a warning on standard error. With `--mount` and an unspecified
address (`0.0.0.0`, `::`), the local mount uses `127.0.0.1` on the same port;
another machine uses this machine's address with that port. The server bounds
its connections and what an unauthenticated one may hold (smb v0.15.0 defaults).
The GUI has no network option: it always serves loopback.

Measured on macOS 27.2.1 (2026-11-16, theca v0.5.0, smb v0.15.0):
`serve --network --addr 0.0.0.0:4455 --mount --credentials-out f` mounted in
`/Volumes/theca`, and `smbutil statshares -a` reported SMB 3.1.1 with
`SMB_CURR_ENCRYPT_ALGORITHM AES-128-GCM`, `SMB_CURR_SIGN_ALGORITHM
AES_128_GMAC`, `ENCRYPTION_REQUIRED TRUE` and `SIGNING_REQUIRED TRUE`. A file
written and read back through the mount worked; SIGINT (by PID) left no volume
and no credentials file, and `verify` passed (16384 sectors). Not measured: a
client on another machine.

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
- **Pairing only ADDS a way in.** Under policy `any` the password alone (and the
  recovery code alone) still open the container after `enroll-key`. It says
  which still do, and prints the command that removes the password-only slot.
  `enroll-key --require` does it in the same run: after pairing the key is
  touched once more to prove the password with the key opens the container, and
  only then is the password-only slot removed (nothing is removed if the proof
  fails; the pairing stays). It does NOT remove the recovery-only slot: that
  code is the way in if the key is lost, so under policy `any` it still opens
  the container alone until you run `slots remove --remove recovery --keep
  password+fido2` (then a lost key means a lost container). A recovery code that
  was not presented cannot be tested, and the output says so.
- **Naming a key.** `fido name set "desk key"` (go-authn/fido `cmd/fido`) stores
  a name ON the key; theca reads it with no touch and no PIN, shows the key by
  that name, and `--device "desk key"` finds it wherever it is plugged (exactly;
  a name on two keys is refused). A key that will not answer that read is chosen
  by id.
- **Which key.** With one key attached, that key is used. With several, theca
  never takes "the first": `--device ID` names one (the ids are what
  `fido list` from [go-authn/fido](https://github.com/go-authn/fido) prints:
  `iokit:<location>` on macOS, the USB port on Linux), and without it you touch
  the key to use (CTAP 2.1 authenticatorSelection) within 30 seconds. Two keys
  touched together are refused. The key is named on stderr before anything is
  asked of it, and `enroll-key` says which key it paired
  (`ok: the key YubiKey Bio (…) is paired with 2 factor(s)`). On Windows the
  system dialog chooses, and `--device` is refused.
- Nothing about the key is written into the container but its pairwise
  slots. The key is asked once per unlock, for all its Theca credentials (one
  touch).
- A key with a fingerprint enrolled (CTAP option `uv` true, e.g. a YubiKey Bio)
  verifies with it: one fingerprint per unlock, no second touch. A fingerprint
  that is not recognised is retried while the key has tries left (the count is
  shown); when it is blocked, exhausted, or none is enrolled, theca says so
  ("the fingerprint is blocked — using the PIN.") and asks for the PIN instead, if one is set.
- A key without a fingerprint asks for its PIN. It is read from `--pin-file`
  (mode `0600` or stricter) or from the terminal, never from an argument.
- What each OS does (the transport is chosen by `GOOS`):

  | OS | Route | PIN and prompts | Status |
  | --- | --- | --- | --- |
  | macOS | CTAP over IOKit HID (go-macos/fido) | theca asks: `--pin-file` or the terminal | measured on a YubiKey 5, firmware 5.7.4 |
  | Linux | CTAP over `/dev/hidraw*` (go-gnulinux/fido), pure Go | theca asks, as on macOS | fakes and a kernel-made HID device only; **not measured on a real key** |
  | Windows | `webauthn.dll` (go-mswin/webauthn), because Windows 10 1903+ refuses raw HID to a process that is not elevated | **Windows asks**: a Windows Security dialog collects the PIN or fingerprint, so `--pin-file` does not apply | fakes and struct layouts only; **not measured on a real key** |

  On Linux `/dev/hidraw*` belongs to root on a stock system: install a udev
  rule giving your user access to FIDO keys (libfido2's `70-u2f.rules`); theca
  then says "a security key is attached but this user cannot open it" instead
  of "no key". On Windows, hmac-secret needs WebAuthn API version 6
  (`webauthn.h`; Windows 11 reports 9). When several Theca credentials are on
  the key, Windows has the person pick one, and only that one is tried.

Design and trade-offs: [docs/HARDWARE-KEYS.md](docs/HARDWARE-KEYS.md) §9
"H2 revised", and [docs/DESIGN.md](docs/DESIGN.md) §19 I21.

### Rollback counter: a TPM 2.0 NV counter

```sh
theca create vault.theca --size 1G --counter tpm                 # defines an NV counter, binds the container to it
theca info   vault.theca --counter tpm                           # rollback protected: true (TPM NV counter 0x01500000 ...)
theca create v2.theca --size 1G --counter tpm --tpm-owner-auth-from keychain:tpm/owner --tpm-endorsement-auth-from keychain:tpm/endorsement
theca info   vault.theca --counter tpm --accept-rollback          # accept an older copy on purpose (loud); needs the counter
theca counter rebind vault.theca --counter tpm --tpm-owner-auth-from keychain:tpm/owner   # the counter is gone: bind to a new one
```

- Asking for the counter means requiring it. A container whose header names no
  counter (made without one, or an older copy from before `counter rebind`
  bound it) is refused under `--counter tpm` (or a profile's `counter = "tpm"`)
  with "this container has no rollback counter, but --counter tpm was asked: an
  older copy may have been restored"; a library caller that passes a counter
  gets `ErrCounterRequired`. The TPM cannot judge a copy that never named it.
- The counter advances once per mount, not per commit. An older copy of the
  container (any earlier session) is refused with `ErrRollback` before anything
  is written; the copy taken during the current session is the window that
  stays open (DESIGN §5.4).
- Every command that opens the container needs `--counter tpm` again (and
  `--tpm-auth-from` if an older theca stored one), **and opens the file read-write**, because
  a mount rebinds the header. Without the flag, a protected container is
  refused with a message naming it.
- `--tpm-device`: a device path, or `unix:SOCKET` for a software TPM
  (`swtpm socket --tpm2 --server type=unixio,path=SOCKET ...`). The default is
  `/dev/tpmrm0` on Linux, which needs permission to open it (usually the
  `tss` group). On Windows the default is TPM Base Services (`tbs:`, through
  go-tpm2/devtpm's `OpenTBS`); name `tbs:` explicitly on any platform to
  select it (off Windows it says it is unsupported). **Windows is measured
  only as far as `TBS_E_TPM_NOT_FOUND`** on a Windows 11 VM without a TPM; a
  counter through a real TPM there has not been run. macOS has no TPM and
  says so unless a device is named.
- **The counter's authValue is derived from the container (v0.19.0).** With no
  `--tpm-auth-*` flag, a new counter's authValue is an HKDF of the container's
  master key: whoever unlocks the container (password plus security key) can
  use its counter, nobody else, and **there is nothing to store**. The header
  records it, so a mount needs only `--counter tpm`. A counter made by an older
  theca keeps its stored authValue (`--tpm-auth-from REF`, or the deprecated
  `--tpm-auth-file`, at every mount); `theca counter rebind` without those flags
  moves it to a derived one.
- **TPM passwords come from a secret manager.** `--tpm-owner-auth-from REF`
  (`create`, `counter rebind`) and `--tpm-endorsement-auth-from REF` (`create`,
  `counter rebind` and **every mount**, only on a TPM whose endorsement
  hierarchy has a password) take `keychain:`, `secretservice:` or `keepassxc:`
  references; a `file:` reference is refused (`--tpm-auth-from` too, since
  v0.21.0). `--tpm-owner-auth-file` and
  `--tpm-auth-file` still work (0600 or stricter) and are deprecated. Never
  arguments or environment variables. Without `--tpm-endorsement-auth-from` on
  such a TPM a pinned container is refused, and the message names the flag. A
  wrong endorsement password does **not** count toward the TPM's
  dictionary-attack lockout (the authValue of a hierarchy other than lockout is
  not DA protected: TCG TPM 2.0 Part 1 rev 1.59, 19.8.1), so a mistake cannot
  lock the TPM; for the same reason it is not throttled against guessing, so
  use a long random one.
- **When the counter is gone** (the owner undefined the index, or
  `TPM2_Clear`, a BIOS reset or a reinstall removed it; an index with
  `POLICY_DELETE` would need platform authorization, so the owner can delete
  this one) the container cannot be opened, and the message says so and names
  `theca counter rebind FILE --counter tpm --tpm-owner-auth-from REF`. That
  command needs the factors that open the container AND the TPM owner
  password; it defines a counter (at the recorded handle if free, else the
  first free one), binds the header to it and increments it. A healthy old
  counter is **deleted first** (otherwise a copy made just before the rebind
  would still open with it). **Rollback protection then restarts from that
  moment**: nothing is checked against the old counter. An old copy of the
  container shows the same refusal as a reset TPM: do not rebind to open one. `--accept-rollback` is another thing: it needs a counter that
  exists and is ahead of the container.
- **The TPM is pinned (v0.18.0).** `create` and `counter rebind` record, in
  the authenticated header, the identity of the TPM the counter is on: the
  digest of the Name of its endorsement key (the EK Credential Profile ECC
  P-256 template, created transiently and flushed, never persistent). Every
  mount compares it **before reading the counter**; a counter on another TPM
  is refused, naming both identities (first 6 bytes in hex) and the recovery:
  `theca counter rebind`, only if you really replaced the TPM. `info` shows
  `counter TPM identity: <hex>`. On a TPM with an endorsement password, give
  `--tpm-endorsement-auth-from` (above); without it the mount is refused. Containers made before
  v0.18.0 carry no identity: they **open as before, with a warning** at every
  mount, until `theca counter rebind` pins them (it replaces the counter, so
  protection restarts from that moment).
- **Threat model**, by attacker.
  - *Replaces the container file with an older copy* (a stolen backup, a
    sync client): stopped by the counter, as before.
  - *Brings another TPM* (a fresh software TPM, a replaced TPM, another
    machine's) and defines the same index on it at the old bound: stopped
    since v0.18.0, by the pinned identity. Not stopped in a container made
    before v0.18.0 and not rebound.
  - *Controls the TPM in use*: the host of a virtual TPM, a program standing
    between theca and the TPM (a replaced device or socket). **Not stopped.**
    The identity names a TPM, it does not prove that the TPM answering is that
    one: the EK public is not secret and whoever is the TPM can present it.
  - *Holds a copy of the TPM's state* (a software TPM's state directory, a VM
    snapshot): it holds the endorsement seed, so it is the same TPM, and it
    can roll the counter back with the state. **Not stopped.**
  - *Forges the answers on the bus to a discrete TPM*: not stopped.
    `TPM2_NV_Certify` under an attestation key would authenticate the answers;
    it was weighed and deferred (DESIGN 5.4.1), because it does not change the
    outcome against the other attackers.

  The counter index has `NO_DA`: a wrong authValue file does not count
  towards the TPM's lockout.
- Library: `tpmcounter.Create`, `tpmcounter.Open`, `tpmcounter.Counter.Identity`
  (`theca.IdentifiedCounter`), `OpenOptions.CounterFor`, `OpenOptions.RebindFor`.
  Built on go-tpm2/tpm2 v0.11.0 `NVDefineCounter`, `NVIncrementAuth`,
  `NVReadCounter`, `EKIdentity`. Counters defined by v0.9.0 (without `NO_DA`) are
  still recognized. One counter per container.

Not in this version: slot management for FIDO2
factor sets on the command line (`slots` handles the
password and the recovery code).

### Keys in memory (go-theca/theca#68)

While a container is open its keys are in RAM, and for hours in the `open`
daemon. What `theca` does about it, and what it does not:

- **Wiped after use.** The password, the PIN and the recovery code are `[]byte`
  from the moment they are read (terminal, owner-only file, secret manager) and
  are cleared once used, and no `string` copy of any of them is made: the PIN
  goes to the FIDO2 library through its `[]byte` call (go-authn/fido v0.15.0,
  `PINTokenBytes`), and `create` prints the recovery code it just made from a
  `[]byte` it then wipes (`theca.Create` returns it as `[]byte`).
- **Known remaining copies, not wiped.** The AES round keys are wiped on
  `Close` (`ctr.Cipher.Zeroize`), but only on the accelerated path (arm64 and
  amd64 with AES-NI): the `crypto/aes` fallback, used elsewhere, keeps its key
  schedule inside the standard library, where it cannot be cleared, and the key
  expansion's own temporaries are not visible from here (go-encryptions/ctr,
  go-theca/theca#74). The transient key-encryption keys: where they live in a heap slice or in a
  field of a value we own they are cleared, but a `[32]byte` returned by value
  (`kdf.KEK`, `kdf.Pair`) is copied through registers and stack frames, and Go
  cannot address or clear a stack slot it has already moved or left. The pads
  `crypto/hmac` keeps inside its hash states (we use the standard library's, so
  there is no handle to clear them).
- **Not swapped.** The pages that hold the master secret, the slot wrap keys and
  their cipher caches are `mlock`ed (a per-page count, because `munlock` of a
  page undoes every `mlock` of it). `--mlock=auto` (the default) tries and says
  once on stderr if the system refuses (`RLIMIT_MEMLOCK`); `--mlock=required`
  refuses to open instead; `--mlock=off` does not call `mlock`. The copies
  listed above (the fallback's round keys, stack KEKs, `crypto/hmac` pads) are
  **not** pinned.
- **No core file, no debugger.** `theca _serve`, the daemon, sets
  `RLIMIT_CORE` to 0 and, on Linux, `PR_SET_DUMPABLE` to 0 (no core file whatever
  the limit; `ptrace`, `/proc/PID/mem` and `process_vm_readv` refused to a
  process of the same user), on macOS `PT_DENY_ATTACH` (a later attach fails).
  A refusal is a warning, not a stop. Windows and the other systems: nothing.

## Library

```go
f, _ := os.OpenFile("vault.theca", os.O_RDWR, 0)
c, err := theca.Open(ctx, theca.FileBacking{File: f}, theca.Unlock{Password: pw}, theca.OpenOptions{})
// c is an io.ReaderAt and io.WriterAt over the logical volume; Sync commits.
```

### Sharing the files inside (package `share`)

What `theca serve` does, as a library (a GUI imports this, not package main):

```go
s, err := share.Start(ctx, c, share.Options{
	Addr: "127.0.0.1:0", Name: "theca", Sync: 5 * time.Second, Mount: true,
})
if err != nil { // share.ErrNoFilesystem: no exFAT inside
	return err
}
fmt.Println(s.URL(), s.MountPath()) // smb://127.0.0.1:58738/theca /Volumes/theca
// <-s.Done() fires when a commit or the server fails; s.Err() says why.
err = s.Stop() // unmount, close the server, close the filesystem (idempotent)
c.Close()      // the caller closes the container, after Stop
```

`share.Format(c)` makes a fresh container shareable: it lays exFAT onto the
volume through the container (what `create --fs exfat` does).

Only a loopback address is served. `Password()` exists to hand the account to
another client; it is a secret, never to be shown or logged.

## License

BSD-3-Clause.
