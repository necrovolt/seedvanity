// C part of seedvanity: PBKDF2-HMAC-SHA512 with the ARMv8.2 SHA-512 instructions.
#include <stddef.h>
#include <stdint.h>
int cpu_has_sha512(void);
// key <= 128 bytes (pre-hash longer keys), salt <= 107 bytes, one 64-byte output block
void cpu_pbkdf2_sha512(const uint8_t *key, size_t keylen, const uint8_t *salt, size_t saltlen,
                       uint32_t iters, uint8_t out[64]);
// Two derivations at once (about 1.5-2x the throughput of two single calls on one core)
void cpu_pbkdf2_sha512_x2(const uint8_t *key0, size_t len0, const uint8_t *key1, size_t len1,
                          const uint8_t *salt, size_t saltlen, uint32_t iters, uint8_t out0[64], uint8_t out1[64]);
