// Package bench measures Theca's sector path and its KDF against C
// references: libsodium (XChaCha20, Argon2id) and OpenSSL (AES-256-CTR,
// HMAC-SHA-256), on one core, with go-scikit/refbench.
//
// It is a separate module so that cgo never enters the library's build. The
// libraries come from pkgx, not from the host:
//
//	cd bench
//	pkgx +libsodium.org +openssl.org +freedesktop.org/pkg-config -- go test -run TestParity .
//	pkgx +libsodium.org +openssl.org +freedesktop.org/pkg-config -- go test -run TestPerf -cpu 1 -perf.run .
package bench

/*
#cgo pkg-config: libsodium libcrypto
#cgo CFLAGS: -O2
#include <stdlib.h>
int ref_init(const unsigned char *ka, const unsigned char *km);
int loop_xchacha(unsigned char *buf, const unsigned char *nonce, const unsigned char *kc, long iters);
int loop_aesctr(unsigned char *buf, const unsigned char *iv, long iters);
int loop_tag(unsigned char *out, const unsigned char *prefix, int plen, const unsigned char *ct, long iters);
int loop_seal(unsigned char *dst, const unsigned char *plain, const unsigned char *seed,
              const unsigned char *kc, const unsigned char *prefix, int plen,
              unsigned char *out, long iters);
int loop_open(unsigned char *dst, const unsigned char *ct, const unsigned char *seed,
              const unsigned char *kc, const unsigned char *prefix, int plen,
              const unsigned char *want, long iters);
int loop_argon2id(unsigned char *out, const char *pw, long pwlen, const unsigned char *salt,
                  unsigned long long t, size_t memBytes, long iters);
const char *ref_sodium_version(void);
const char *ref_openssl_version(void);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// SectorSize is the sector every case processes.
const SectorSize = 4096

func p(b []byte) *C.uchar { return (*C.uchar)(unsafe.Pointer(&b[0])) }

func check(rc C.int, what string) error {
	if rc != 0 {
		return fmt.Errorf("%s: C reference returned %d", what, int(rc))
	}
	return nil
}

// Init sets up the reusable OpenSSL contexts with the AES and MAC keys.
func Init(ka, km []byte) error { return check(C.ref_init(p(ka), p(km)), "init") }

// XChaCha20 XORs buf (one sector) with libsodium's XChaCha20 keystream, iters times.
func XChaCha20(buf, nonce, kc []byte, iters int) error {
	return check(C.loop_xchacha(p(buf), p(nonce), p(kc), C.long(iters)), "xchacha20")
}

// AES256CTR XORs buf with OpenSSL's AES-256-CTR keystream from iv, iters times.
func AES256CTR(buf, iv []byte, iters int) error {
	return check(C.loop_aesctr(p(buf), p(iv), C.long(iters)), "aes-256-ctr")
}

// Tag computes HMAC-SHA-256(Km, prefix || ct) into out (32 bytes), iters times.
func Tag(out, prefix, ct []byte, iters int) error {
	return check(C.loop_tag(p(out), p(prefix), C.int(len(prefix)), p(ct), C.long(iters)), "hmac")
}

// Seal runs the whole TA1 sector seal iters times.
func Seal(dst, plain, seed, kc, prefix, out []byte, iters int) error {
	return check(C.loop_seal(p(dst), p(plain), p(seed), p(kc), p(prefix), C.int(len(prefix)), p(out), C.long(iters)), "seal")
}

// Open checks the 24-byte tag want and decrypts ct into dst, iters times.
func Open(dst, ct, seed, kc, prefix, want []byte, iters int) error {
	return check(C.loop_open(p(dst), p(ct), p(seed), p(kc), p(prefix), C.int(len(prefix)), p(want), C.long(iters)), "open")
}

// Argon2id runs libsodium's crypto_pwhash (Argon2id v1.3, one lane) iters times.
func Argon2id(out []byte, pw string, salt []byte, t uint32, memKiB uint32, iters int) error {
	cpw := C.CString(pw)
	defer C.free(unsafe.Pointer(cpw))
	return check(C.loop_argon2id(p(out), cpw, C.long(len(pw)), p(salt), C.ulonglong(t), C.size_t(memKiB)*1024, C.long(iters)), "argon2id")
}

// Versions names the C libraries actually linked.
func Versions() map[string]string {
	return map[string]string{
		"libsodium": C.GoString(C.ref_sodium_version()),
		"OpenSSL":   C.GoString(C.ref_openssl_version()),
	}
}
