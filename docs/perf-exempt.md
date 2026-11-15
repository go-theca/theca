# Public functions without a performance case

Read by `refbench` in its CI mode (`cd bench && go test -run TestPerf .`). Every public function of the module either has a case in `bench/perf_test.go` or is named here with its reason. The cases cover the two paths whose speed users feel: the sector path (`Container.WriteAt`, `Container.ReadAt`) and the password KDF (`PasswordFactor`).

- `Create`: Argon2id (the `PasswordFactor` case), then one pass of ChaCha20 filler over the file, then the slot seals. There is no C program that formats a Theca container to compare against.
- `Open`: Argon2id (the `PasswordFactor` case) plus 16 slot trial-opens of 2 KiB each. No C counterpart.
- `Container.Verify`: one `Sector/Open` per written sector plus the tree walk. Its per-sector cost is the `Sector/Open` row.
- `Container.Sync`: the journal commit, i.e. sealed records, two flushes and a header seal. It is bounded by the backing's flush latency, not by computation, and there is no C counterpart.
- `Container.Close`: `Sync`, then the keys are wiped.
- `Container.AddSlot`: one slot seal (2 KiB, TA1) and a commit. Rare and interactive.
- `Container.RemoveSlot`: one 2 KiB random write and a commit. Rare and interactive.
- `Container.EnrollFIDO2`: dominated by the user's touch on the key.
- `Container.Info`: a copy of a small struct.
- `Container.Size`: a multiplication.
- `RecoveryFactor`: parses 33 characters and runs one HKDF. No KDF cost by design (160 bits of entropy).
- `FIDO2Factor`: one HKDF.
- `Factor.Zeroize`: clears 32 bytes.
- `FileBacking.Size`: one `fstat`.
