// PBKDF2-HMAC-SHA512 on the CPU with the ARMv8.2 SHA-512 instructions (Apple M1 and newer).
// Round structure follows the Linux kernel sha512-ce-core.S (Ard Biesheuvel), as used by Go's
// crypto/sha512 on arm64. Checked against CommonCrypto by the tool's self-test.
#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>
#include "cpu_pbkdf2.h"

// generated: SHA-512 round constants and IV
static const uint64_t K512[80] = {
  0x428a2f98d728ae22ULL,
  0x7137449123ef65cdULL,
  0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,
  0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL,
  0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL,
  0x243185be4ee4b28cULL,
  0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,
  0x80deb1fe3b1696b1ULL,
  0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,
  0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL,
  0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL,
  0x5cb0a9dcbd41fbd4ULL,
  0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,
  0xa831c66d2db43210ULL,
  0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,
  0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL,
  0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL,
  0x4d2c6dfc5ac42aedULL,
  0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,
  0x766a0abb3c77b2a8ULL,
  0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,
  0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL,
  0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL,
  0xf40e35855771202aULL,
  0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,
  0x1e376c085141ab53ULL,
  0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,
  0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL,
  0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL,
  0x84c87814a1f0ab72ULL,
  0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,
  0xa4506cebde82bde9ULL,
  0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL,
  0xca273eceea26619cULL,
  0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL,
  0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL,
  0x113f9804bef90daeULL,
  0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,
  0x32caab7b40c72493ULL,
  0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,
  0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL,
  0x6c44198c4a475817ULL
};
static const uint64_t IV512[8] = {
  0x6a09e667f3bcc908ULL,
  0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL,
  0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL,
  0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL,
  0x5be0cd19137e2179ULL
};

// One dual round: 2 of the 80 rounds, plus the message schedule update for in0.
#define DROUND(i0, i1, i2, i3, i4, r, in0, in1, in2, in3, in4) do {    \
        uint64x2_t t5 = vaddq_u64(in0, vld1q_u64(&K512[2 * (r)]));      \
        uint64x2_t t6 = vextq_u64(i2, i3, 1);                           \
        t5 = vextq_u64(t5, t5, 1);                                      \
        uint64x2_t t7 = vextq_u64(i1, i2, 1);                           \
        i3 = vaddq_u64(i3, t5);                                         \
        t5 = vextq_u64(in3, in4, 1);                                    \
        in0 = vsha512su0q_u64(in0, in1);                                \
        i3 = vsha512hq_u64(i3, t6, t7);                                 \
        in0 = vsha512su1q_u64(in0, in2, t5);                            \
        i4 = vaddq_u64(i1, i3);                                         \
        i3 = vsha512h2q_u64(i3, i1, i0);                                \
    } while (0)
// Same without the message schedule update (last 8 dual rounds).
#define DROUND_NU(i0, i1, i2, i3, i4, r, in0) do {                      \
        uint64x2_t t5 = vaddq_u64(in0, vld1q_u64(&K512[2 * (r)]));      \
        uint64x2_t t6 = vextq_u64(i2, i3, 1);                           \
        t5 = vextq_u64(t5, t5, 1);                                      \
        uint64x2_t t7 = vextq_u64(i1, i2, 1);                           \
        i3 = vaddq_u64(i3, t5);                                         \
        i3 = vsha512hq_u64(i3, t6, t7);                                 \
        i4 = vaddq_u64(i1, i3);                                         \
        i3 = vsha512h2q_u64(i3, i1, i0);                                \
    } while (0)

// st: 8 state words, w: 16 message words (numeric values, i.e. already big-endian decoded)
__attribute__((target("sha3"), always_inline))
static inline void compress(uint64_t st[8], const uint64_t w[16]) {
    uint64x2_t s0 = vld1q_u64(st), s1 = vld1q_u64(st + 2), s2 = vld1q_u64(st + 4), s3 = vld1q_u64(st + 6), s4;
    const uint64x2_t o0 = s0, o1 = s1, o2 = s2, o3 = s3;
    uint64x2_t m0 = vld1q_u64(w), m1 = vld1q_u64(w + 2), m2 = vld1q_u64(w + 4), m3 = vld1q_u64(w + 6);
    uint64x2_t m4 = vld1q_u64(w + 8), m5 = vld1q_u64(w + 10), m6 = vld1q_u64(w + 12), m7 = vld1q_u64(w + 14);
    DROUND(s0, s1, s2, s3, s4, 0, m0, m1, m7, m4, m5);
    DROUND(s3, s0, s4, s2, s1, 1, m1, m2, m0, m5, m6);
    DROUND(s2, s3, s1, s4, s0, 2, m2, m3, m1, m6, m7);
    DROUND(s4, s2, s0, s1, s3, 3, m3, m4, m2, m7, m0);
    DROUND(s1, s4, s3, s0, s2, 4, m4, m5, m3, m0, m1);
    DROUND(s0, s1, s2, s3, s4, 5, m5, m6, m4, m1, m2);
    DROUND(s3, s0, s4, s2, s1, 6, m6, m7, m5, m2, m3);
    DROUND(s2, s3, s1, s4, s0, 7, m7, m0, m6, m3, m4);
    DROUND(s4, s2, s0, s1, s3, 8, m0, m1, m7, m4, m5);
    DROUND(s1, s4, s3, s0, s2, 9, m1, m2, m0, m5, m6);
    DROUND(s0, s1, s2, s3, s4, 10, m2, m3, m1, m6, m7);
    DROUND(s3, s0, s4, s2, s1, 11, m3, m4, m2, m7, m0);
    DROUND(s2, s3, s1, s4, s0, 12, m4, m5, m3, m0, m1);
    DROUND(s4, s2, s0, s1, s3, 13, m5, m6, m4, m1, m2);
    DROUND(s1, s4, s3, s0, s2, 14, m6, m7, m5, m2, m3);
    DROUND(s0, s1, s2, s3, s4, 15, m7, m0, m6, m3, m4);
    DROUND(s3, s0, s4, s2, s1, 16, m0, m1, m7, m4, m5);
    DROUND(s2, s3, s1, s4, s0, 17, m1, m2, m0, m5, m6);
    DROUND(s4, s2, s0, s1, s3, 18, m2, m3, m1, m6, m7);
    DROUND(s1, s4, s3, s0, s2, 19, m3, m4, m2, m7, m0);
    DROUND(s0, s1, s2, s3, s4, 20, m4, m5, m3, m0, m1);
    DROUND(s3, s0, s4, s2, s1, 21, m5, m6, m4, m1, m2);
    DROUND(s2, s3, s1, s4, s0, 22, m6, m7, m5, m2, m3);
    DROUND(s4, s2, s0, s1, s3, 23, m7, m0, m6, m3, m4);
    DROUND(s1, s4, s3, s0, s2, 24, m0, m1, m7, m4, m5);
    DROUND(s0, s1, s2, s3, s4, 25, m1, m2, m0, m5, m6);
    DROUND(s3, s0, s4, s2, s1, 26, m2, m3, m1, m6, m7);
    DROUND(s2, s3, s1, s4, s0, 27, m3, m4, m2, m7, m0);
    DROUND(s4, s2, s0, s1, s3, 28, m4, m5, m3, m0, m1);
    DROUND(s1, s4, s3, s0, s2, 29, m5, m6, m4, m1, m2);
    DROUND(s0, s1, s2, s3, s4, 30, m6, m7, m5, m2, m3);
    DROUND(s3, s0, s4, s2, s1, 31, m7, m0, m6, m3, m4);
    DROUND_NU(s2, s3, s1, s4, s0, 32, m0);
    DROUND_NU(s4, s2, s0, s1, s3, 33, m1);
    DROUND_NU(s1, s4, s3, s0, s2, 34, m2);
    DROUND_NU(s0, s1, s2, s3, s4, 35, m3);
    DROUND_NU(s3, s0, s4, s2, s1, 36, m4);
    DROUND_NU(s2, s3, s1, s4, s0, 37, m5);
    DROUND_NU(s4, s2, s0, s1, s3, 38, m6);
    DROUND_NU(s1, s4, s3, s0, s2, 39, m7);
    (void)s4;
    vst1q_u64(st, vaddq_u64(s0, o0));
    vst1q_u64(st + 2, vaddq_u64(s1, o1));
    vst1q_u64(st + 4, vaddq_u64(s2, o2));
    vst1q_u64(st + 6, vaddq_u64(s3, o3));
}

static inline uint64_t be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

int cpu_has_sha512(void) {
    int v = 0;
    size_t n = sizeof(v);
    if (sysctlbyname("hw.optional.armv8_2_sha512", &v, &n, NULL, 0) != 0) return 0;
    return v;
}

__attribute__((target("sha3")))
void cpu_pbkdf2_sha512(const uint8_t *key, size_t keylen, const uint8_t *salt, size_t saltlen,
                       uint32_t iters, uint8_t out[64]) {
    uint8_t kb[128] = {0}, blk[128] = {0};
    uint64_t w[16], ist[8], ost[8], u[8], t[8], s[8];
    if (keylen > 128 || saltlen > 107 || iters == 0) { memset(out, 0, 64); return; }
    memcpy(kb, key, keylen);
    for (int j = 0; j < 16; j++) w[j] = be64(kb + 8 * j) ^ 0x3636363636363636ULL;
    memcpy(ist, IV512, 64); compress(ist, w);
    for (int j = 0; j < 16; j++) w[j] = be64(kb + 8 * j) ^ 0x5c5c5c5c5c5c5c5cULL;
    memcpy(ost, IV512, 64); compress(ost, w);

    // U1 = HMAC(key, salt || INT(1))
    memcpy(blk, salt, saltlen);
    blk[saltlen + 3] = 1;
    blk[saltlen + 4] = 0x80;
    uint64_t bits = (uint64_t)(128 + saltlen + 4) * 8;
    for (int j = 0; j < 8; j++) blk[120 + j] = (uint8_t)(bits >> (56 - 8 * j));
    for (int j = 0; j < 16; j++) w[j] = be64(blk + 8 * j);
    memcpy(s, ist, 64); compress(s, w);
    for (int j = 0; j < 8; j++) w[j] = s[j];
    w[8] = 0x8000000000000000ULL; w[9] = w[10] = w[11] = w[12] = w[13] = w[14] = 0; w[15] = (128 + 64) * 8;
    memcpy(u, ost, 64); compress(u, w);
    memcpy(t, u, 64);

    for (uint32_t it = 1; it < iters; it++) {
        for (int j = 0; j < 8; j++) w[j] = u[j];          // w[8..15] keep the fixed padding
        memcpy(s, ist, 64); compress(s, w);
        for (int j = 0; j < 8; j++) w[j] = s[j];
        memcpy(u, ost, 64); compress(u, w);
        for (int j = 0; j < 8; j++) t[j] ^= u[j];
    }
    for (int j = 0; j < 8; j++)
        for (int b = 0; b < 8; b++) out[8 * j + b] = (uint8_t)(t[j] >> (56 - 8 * b));
}

// Two independent compressions interleaved: hides the latency of the SHA-512 instructions.
__attribute__((target("sha3"), always_inline))
static inline void compress2(uint64_t sta[8], const uint64_t wa[16], uint64_t stb[8], const uint64_t wb[16]) {
    uint64x2_t s0a = vld1q_u64(sta), s1a = vld1q_u64(sta + 2), s2a = vld1q_u64(sta + 4), s3a = vld1q_u64(sta + 6), s4a;
    const uint64x2_t o0a = s0a, o1a = s1a, o2a = s2a, o3a = s3a;
    uint64x2_t m0a = vld1q_u64(wa + 0), m1a = vld1q_u64(wa + 2), m2a = vld1q_u64(wa + 4), m3a = vld1q_u64(wa + 6), m4a = vld1q_u64(wa + 8), m5a = vld1q_u64(wa + 10), m6a = vld1q_u64(wa + 12), m7a = vld1q_u64(wa + 14);
    uint64x2_t s0b = vld1q_u64(stb), s1b = vld1q_u64(stb + 2), s2b = vld1q_u64(stb + 4), s3b = vld1q_u64(stb + 6), s4b;
    const uint64x2_t o0b = s0b, o1b = s1b, o2b = s2b, o3b = s3b;
    uint64x2_t m0b = vld1q_u64(wb + 0), m1b = vld1q_u64(wb + 2), m2b = vld1q_u64(wb + 4), m3b = vld1q_u64(wb + 6), m4b = vld1q_u64(wb + 8), m5b = vld1q_u64(wb + 10), m6b = vld1q_u64(wb + 12), m7b = vld1q_u64(wb + 14);
    DROUND(s0a, s1a, s2a, s3a, s4a, 0, m0a, m1a, m7a, m4a, m5a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 0, m0b, m1b, m7b, m4b, m5b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 1, m1a, m2a, m0a, m5a, m6a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 1, m1b, m2b, m0b, m5b, m6b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 2, m2a, m3a, m1a, m6a, m7a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 2, m2b, m3b, m1b, m6b, m7b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 3, m3a, m4a, m2a, m7a, m0a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 3, m3b, m4b, m2b, m7b, m0b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 4, m4a, m5a, m3a, m0a, m1a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 4, m4b, m5b, m3b, m0b, m1b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 5, m5a, m6a, m4a, m1a, m2a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 5, m5b, m6b, m4b, m1b, m2b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 6, m6a, m7a, m5a, m2a, m3a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 6, m6b, m7b, m5b, m2b, m3b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 7, m7a, m0a, m6a, m3a, m4a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 7, m7b, m0b, m6b, m3b, m4b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 8, m0a, m1a, m7a, m4a, m5a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 8, m0b, m1b, m7b, m4b, m5b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 9, m1a, m2a, m0a, m5a, m6a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 9, m1b, m2b, m0b, m5b, m6b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 10, m2a, m3a, m1a, m6a, m7a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 10, m2b, m3b, m1b, m6b, m7b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 11, m3a, m4a, m2a, m7a, m0a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 11, m3b, m4b, m2b, m7b, m0b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 12, m4a, m5a, m3a, m0a, m1a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 12, m4b, m5b, m3b, m0b, m1b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 13, m5a, m6a, m4a, m1a, m2a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 13, m5b, m6b, m4b, m1b, m2b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 14, m6a, m7a, m5a, m2a, m3a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 14, m6b, m7b, m5b, m2b, m3b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 15, m7a, m0a, m6a, m3a, m4a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 15, m7b, m0b, m6b, m3b, m4b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 16, m0a, m1a, m7a, m4a, m5a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 16, m0b, m1b, m7b, m4b, m5b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 17, m1a, m2a, m0a, m5a, m6a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 17, m1b, m2b, m0b, m5b, m6b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 18, m2a, m3a, m1a, m6a, m7a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 18, m2b, m3b, m1b, m6b, m7b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 19, m3a, m4a, m2a, m7a, m0a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 19, m3b, m4b, m2b, m7b, m0b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 20, m4a, m5a, m3a, m0a, m1a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 20, m4b, m5b, m3b, m0b, m1b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 21, m5a, m6a, m4a, m1a, m2a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 21, m5b, m6b, m4b, m1b, m2b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 22, m6a, m7a, m5a, m2a, m3a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 22, m6b, m7b, m5b, m2b, m3b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 23, m7a, m0a, m6a, m3a, m4a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 23, m7b, m0b, m6b, m3b, m4b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 24, m0a, m1a, m7a, m4a, m5a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 24, m0b, m1b, m7b, m4b, m5b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 25, m1a, m2a, m0a, m5a, m6a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 25, m1b, m2b, m0b, m5b, m6b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 26, m2a, m3a, m1a, m6a, m7a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 26, m2b, m3b, m1b, m6b, m7b);
    DROUND(s2a, s3a, s1a, s4a, s0a, 27, m3a, m4a, m2a, m7a, m0a);
    DROUND(s2b, s3b, s1b, s4b, s0b, 27, m3b, m4b, m2b, m7b, m0b);
    DROUND(s4a, s2a, s0a, s1a, s3a, 28, m4a, m5a, m3a, m0a, m1a);
    DROUND(s4b, s2b, s0b, s1b, s3b, 28, m4b, m5b, m3b, m0b, m1b);
    DROUND(s1a, s4a, s3a, s0a, s2a, 29, m5a, m6a, m4a, m1a, m2a);
    DROUND(s1b, s4b, s3b, s0b, s2b, 29, m5b, m6b, m4b, m1b, m2b);
    DROUND(s0a, s1a, s2a, s3a, s4a, 30, m6a, m7a, m5a, m2a, m3a);
    DROUND(s0b, s1b, s2b, s3b, s4b, 30, m6b, m7b, m5b, m2b, m3b);
    DROUND(s3a, s0a, s4a, s2a, s1a, 31, m7a, m0a, m6a, m3a, m4a);
    DROUND(s3b, s0b, s4b, s2b, s1b, 31, m7b, m0b, m6b, m3b, m4b);
    DROUND_NU(s2a, s3a, s1a, s4a, s0a, 32, m0a);
    DROUND_NU(s2b, s3b, s1b, s4b, s0b, 32, m0b);
    DROUND_NU(s4a, s2a, s0a, s1a, s3a, 33, m1a);
    DROUND_NU(s4b, s2b, s0b, s1b, s3b, 33, m1b);
    DROUND_NU(s1a, s4a, s3a, s0a, s2a, 34, m2a);
    DROUND_NU(s1b, s4b, s3b, s0b, s2b, 34, m2b);
    DROUND_NU(s0a, s1a, s2a, s3a, s4a, 35, m3a);
    DROUND_NU(s0b, s1b, s2b, s3b, s4b, 35, m3b);
    DROUND_NU(s3a, s0a, s4a, s2a, s1a, 36, m4a);
    DROUND_NU(s3b, s0b, s4b, s2b, s1b, 36, m4b);
    DROUND_NU(s2a, s3a, s1a, s4a, s0a, 37, m5a);
    DROUND_NU(s2b, s3b, s1b, s4b, s0b, 37, m5b);
    DROUND_NU(s4a, s2a, s0a, s1a, s3a, 38, m6a);
    DROUND_NU(s4b, s2b, s0b, s1b, s3b, 38, m6b);
    DROUND_NU(s1a, s4a, s3a, s0a, s2a, 39, m7a);
    DROUND_NU(s1b, s4b, s3b, s0b, s2b, 39, m7b);
    (void)s4a;
    vst1q_u64(sta + 0, vaddq_u64(s0a, o0a));
    vst1q_u64(sta + 2, vaddq_u64(s1a, o1a));
    vst1q_u64(sta + 4, vaddq_u64(s2a, o2a));
    vst1q_u64(sta + 6, vaddq_u64(s3a, o3a));
    (void)s4b;
    vst1q_u64(stb + 0, vaddq_u64(s0b, o0b));
    vst1q_u64(stb + 2, vaddq_u64(s1b, o1b));
    vst1q_u64(stb + 4, vaddq_u64(s2b, o2b));
    vst1q_u64(stb + 6, vaddq_u64(s3b, o3b));
}

// Two PBKDF2-HMAC-SHA512 derivations at once (same salt and iteration count).
__attribute__((target("sha3")))
void cpu_pbkdf2_sha512_x2(const uint8_t *key0, size_t len0, const uint8_t *key1, size_t len1,
                          const uint8_t *salt, size_t saltlen, uint32_t iters, uint8_t out0[64], uint8_t out1[64]) {
    const uint8_t *keys[2] = {key0, key1};
    size_t lens[2] = {len0, len1};
    uint8_t *outs[2] = {out0, out1};
    uint64_t ist[2][8], ost[2][8], u[2][8], t[2][8], s[2][8], w[2][16];
    if (len0 > 128 || len1 > 128 || saltlen > 107 || iters == 0) { memset(out0, 0, 64); memset(out1, 0, 64); return; }
    uint8_t blk[128] = {0};
    memcpy(blk, salt, saltlen);
    blk[saltlen + 3] = 1;
    blk[saltlen + 4] = 0x80;
    uint64_t bits = (uint64_t)(128 + saltlen + 4) * 8;
    for (int j = 0; j < 8; j++) blk[120 + j] = (uint8_t)(bits >> (56 - 8 * j));
    for (int x = 0; x < 2; x++) {
        uint8_t kb[128] = {0};
        memcpy(kb, keys[x], lens[x]);
        for (int j = 0; j < 16; j++) w[x][j] = be64(kb + 8 * j) ^ 0x3636363636363636ULL;
        memcpy(ist[x], IV512, 64); compress(ist[x], w[x]);
        for (int j = 0; j < 16; j++) w[x][j] = be64(kb + 8 * j) ^ 0x5c5c5c5c5c5c5c5cULL;
        memcpy(ost[x], IV512, 64); compress(ost[x], w[x]);
        for (int j = 0; j < 16; j++) w[x][j] = be64(blk + 8 * j);
        memcpy(s[x], ist[x], 64); compress(s[x], w[x]);
        for (int j = 0; j < 8; j++) w[x][j] = s[x][j];
        w[x][8] = 0x8000000000000000ULL; w[x][9] = w[x][10] = w[x][11] = w[x][12] = w[x][13] = w[x][14] = 0; w[x][15] = (128 + 64) * 8;
        memcpy(u[x], ost[x], 64); compress(u[x], w[x]);
        memcpy(t[x], u[x], 64);
    }
    for (uint32_t it = 1; it < iters; it++) {
        for (int x = 0; x < 2; x++) { for (int j = 0; j < 8; j++) w[x][j] = u[x][j]; memcpy(s[x], ist[x], 64); }
        compress2(s[0], w[0], s[1], w[1]);
        for (int x = 0; x < 2; x++) { for (int j = 0; j < 8; j++) w[x][j] = s[x][j]; memcpy(u[x], ost[x], 64); }
        compress2(u[0], w[0], u[1], w[1]);
        for (int x = 0; x < 2; x++) for (int j = 0; j < 8; j++) t[x][j] ^= u[x][j];
    }
    for (int x = 0; x < 2; x++)
        for (int j = 0; j < 8; j++)
            for (int b = 0; b < 8; b++) outs[x][8 * j + b] = (uint8_t)(t[x][j] >> (56 - 8 * b));
}
