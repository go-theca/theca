// Reference loops for Theca's sector path, in C: libsodium for XChaCha20 and
// Argon2id, OpenSSL (EVP) for AES-256-CTR and HMAC-SHA-256. One cgo call
// covers many sectors, so the cgo transition does not enter the measurement.
//
// The references use each library the way a careful C implementation would:
// the AES key schedule and the HMAC key are set up once and reused across
// sectors (only the IV, or the MAC state, is reset). Theca rebuilds both per
// sector; the table shows what that costs.

#include <string.h>
#include <sodium.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#define SECTOR 4096

static EVP_CIPHER_CTX *ctr;
static EVP_MAC_CTX *mac;

// ref_init returns 0 on success.
int ref_init(const unsigned char *ka, const unsigned char *km) {
	if (sodium_init() < 0) {
		return 1;
	}
	unsigned char iv[16] = {0};
	ctr = EVP_CIPHER_CTX_new();
	if (ctr == NULL || EVP_EncryptInit_ex(ctr, EVP_aes_256_ctr(), NULL, ka, iv) != 1) {
		return 2;
	}
	EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (m == NULL) {
		return 3;
	}
	mac = EVP_MAC_CTX_new(m);
	EVP_MAC_free(m);
	OSSL_PARAM p[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
		OSSL_PARAM_construct_end(),
	};
	if (mac == NULL || EVP_MAC_init(mac, km, 32, p) != 1) {
		return 4;
	}
	return 0;
}

static void xchacha(unsigned char *buf, const unsigned char *nonce, const unsigned char *kc) {
	crypto_stream_xchacha20_xor(buf, buf, SECTOR, nonce, kc);
}

static int aesctr(unsigned char *buf, const unsigned char *iv) {
	int n = 0;
	if (EVP_EncryptInit_ex(ctr, NULL, NULL, NULL, iv) != 1) {
		return 1;
	}
	return EVP_EncryptUpdate(ctr, buf, &n, buf, SECTOR) != 1 || n != SECTOR;
}

static int tag(unsigned char *out, const unsigned char *prefix, int plen, const unsigned char *ct) {
	size_t n = 0;
	if (EVP_MAC_init(mac, NULL, 0, NULL) != 1) {
		return 1;
	}
	if (EVP_MAC_update(mac, prefix, plen) != 1 || EVP_MAC_update(mac, ct, SECTOR) != 1) {
		return 1;
	}
	return EVP_MAC_final(mac, out, &n, 32) != 1 || n != 32;
}

// Every loop returns 0 on success, non-zero on a library error.

int loop_xchacha(unsigned char *buf, const unsigned char *nonce, const unsigned char *kc, long iters) {
	for (long i = 0; i < iters; i++) {
		xchacha(buf, nonce, kc);
	}
	return 0;
}

int loop_aesctr(unsigned char *buf, const unsigned char *iv, long iters) {
	for (long i = 0; i < iters; i++) {
		if (aesctr(buf, iv)) {
			return 1;
		}
	}
	return 0;
}

int loop_tag(unsigned char *out, const unsigned char *prefix, int plen, const unsigned char *ct, long iters) {
	for (long i = 0; i < iters; i++) {
		if (tag(out, prefix, plen, ct)) {
			return 1;
		}
	}
	return 0;
}

// loop_seal is TA1's sector seal: XChaCha20 xor, AES-256-CTR xor, then the tag
// over the ciphertext. seed is 40 bytes: the XChaCha20 nonce, then the AES IV.
int loop_seal(unsigned char *dst, const unsigned char *plain, const unsigned char *seed,
              const unsigned char *kc, const unsigned char *prefix, int plen,
              unsigned char *out, long iters) {
	for (long i = 0; i < iters; i++) {
		memcpy(dst, plain, SECTOR);
		xchacha(dst, seed, kc);
		if (aesctr(dst, seed + 24) || tag(out, prefix, plen, dst)) {
			return 1;
		}
	}
	return 0;
}

// loop_open checks the tag, then decrypts. A tag mismatch returns 2.
int loop_open(unsigned char *dst, const unsigned char *ct, const unsigned char *seed,
              const unsigned char *kc, const unsigned char *prefix, int plen,
              const unsigned char *want, long iters) {
	unsigned char got[32];
	for (long i = 0; i < iters; i++) {
		if (tag(got, prefix, plen, ct)) {
			return 1;
		}
		if (sodium_memcmp(got, want, 24) != 0) {
			return 2;
		}
		memcpy(dst, ct, SECTOR);
		if (aesctr(dst, seed + 24)) {
			return 1;
		}
		xchacha(dst, seed, kc);
	}
	return 0;
}

int loop_argon2id(unsigned char *out, const char *pw, long pwlen, const unsigned char *salt,
                  unsigned long long t, size_t memBytes, long iters) {
	for (long i = 0; i < iters; i++) {
		if (crypto_pwhash(out, 32, pw, pwlen, salt, t, memBytes, crypto_pwhash_ALG_ARGON2ID13) != 0) {
			return 1;
		}
	}
	return 0;
}

const char *ref_sodium_version(void) { return sodium_version_string(); }
const char *ref_openssl_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
