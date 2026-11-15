# bench

This module measures Theca against C references on one core, with [go-scikit/refbench](https://github.com/go-scikit/refbench). It writes [`docs/perf.json`](../docs/perf.json) and [`docs/perf-table.md`](../docs/perf-table.md).

It is a separate module so that cgo never enters the library's build. The C libraries come from pkgx, not from the host. Their dylibs have `@rpath` install names, so the pkgx root is passed as an rpath at link time:

```sh
cd bench
export CGO_LDFLAGS="-Wl,-rpath,$HOME/.pkgx"
P="pkgx +libsodium.org +openssl.org +freedesktop.org/pkg-config --"

$P go test -run TestParity .                    # both sides give identical bytes
$P go test -run TestPerf .                      # CI mode: allocations, table, exemptions
$P go test -run TestPerf -perf.record .         # allocation counts only (any load)
$P go test -c -o perf.test . && \
  $P ./perf.test -test.cpu 1 -test.run 'TestPerf$' -perf.run -perf.onload=wait -perf.wait=2h
```

| case | Go side | C reference |
|---|---|---|
| `Sector/XChaCha20` | `x/crypto/chacha20`, one cipher per sector (as `internal/ta1`) | libsodium `crypto_stream_xchacha20_xor` |
| `Sector/AES-256-CTR` | `crypto/aes` + `cipher.NewCTR`, one per sector | OpenSSL EVP `aes-256-ctr`, key schedule reused |
| `Sector/Tag (HMAC-SHA-256)` | `ta1.Keys.SectorTag` | OpenSSL `EVP_MAC` HMAC-SHA256, key reused |
| `Sector/Seal`, `Sector/Open` | `ta1.Keys.SealSector`, `OpenSector` | the same composition in C |
| `Argon2id/t3-m64MiB-p1` | `x/crypto/argon2.IDKey`, one lane | libsodium `crypto_pwhash` (Argon2id v1.3) |

The C side uses each library the way a careful C implementation would, reusing key schedules across sectors. A gap in a row therefore includes Theca's own per-sector setup cost, which is a cost of the design and not of the language.

The production Argon2id profiles use four lanes. libsodium implements only one, and the comparison runs on one core anyway, so the row uses profile 1's time and memory with a single lane.
