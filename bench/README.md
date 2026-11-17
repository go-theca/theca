# bench

This module measures Theca against C references on one core, with [go-scikit/refbench](https://github.com/go-scikit/refbench). It writes [`docs/perf.json`](../docs/perf.json) and [`docs/perf-table.md`](../docs/perf-table.md).

It is a separate module so that cgo never enters the library's build. The C libraries come from the fleet's signed registry through [zpkgx](https://github.com/go-zpkg/zpkgx), not from the host. Their libraries have `@rpath` install names, so the store root is passed as an rpath at link time:

```sh
cd bench
eval "$(zpkgx +libsodium.org +openssl.org +freedesktop.org/pkg-config)"
export CGO_LDFLAGS="-Wl,-rpath,$HOME/.pkgx"

gotest -run TestParity .                        # both sides give identical bytes
gotest -run TestPerf .                          # CI mode: allocations, table, exemptions
gotest -run TestPerf -perf.record .             # allocation counts only (any load)
go test -c -o ../../perf.test .                 # outside the tree: a measurement needs a clean one
../../perf.test -test.cpu 1 -test.run 'TestPerf$' -perf.run -perf.onload=wait -perf.wait=2h \
    -perf.commit "$(git rev-parse HEAD)" -perf.machine "<cpu model>, <os/arch>"
```

The table header records the library versions **loaded at run time**, which can differ from what `pkg-config` reported at build time. On 2026-11-15 the Mac build announced OpenSSL 4.0.2 and loaded 3.6.4, while Linux loaded 4.0.2.

Two machines are measured:
- [`docs/perf-table.md`](../docs/perf-table.md): Apple M4 Max.
- [`docs/perf-zen4-table.md`](../docs/perf-zen4-table.md): AMD Ryzen 9 7950X, pinned to one CPU with `taskset`.

On the Zen 4 machine, libsodium's XChaCha20 and Argon2id run far below their usual AVX2 speed (about 440 MB/s, and 4× slower than Go's Argon2id). The registry's libsodium may be built without its SIMD code. Until a control with another libsodium build settles this, the "faster" verdicts in those two rows are **not** claims.

| case | Go side | C reference |
|---|---|---|
| `Sector/XChaCha20` | `x/crypto/chacha20`, one cipher per sector (as `internal/ta1`) | libsodium `crypto_stream_xchacha20_xor` |
| `Sector/AES-256-CTR` | `go-encryptions/ctr`, round keys expanded once, one kernel call per sector | OpenSSL EVP `aes-256-ctr`, key schedule reused |
| `Sector/Tag (HMAC-SHA-256)` | `ta1.Keys.SectorTag` | OpenSSL `EVP_MAC` HMAC-SHA256, key reused |
| `Sector/Seal`, `Sector/Open` | `ta1.Keys.SealSector`, `OpenSector` | the same composition in C |
| `Argon2id/t3-m64MiB-p1` | `go-encryptions/argon2.IDKey` (x/crypto's code, NEON BLAMKA on arm64), one lane | libsodium `crypto_pwhash` (Argon2id v1.3) |

The C side uses each library the way a careful C implementation would, reusing key schedules across sectors. A gap in a row therefore includes Theca's own per-sector setup cost, which is a cost of the design and not of the language.

The production Argon2id profiles use four lanes. libsodium implements only one, and the comparison runs on one core anyway, so the row uses profile 1's time and memory with a single lane.
