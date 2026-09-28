// PBKDF2-HMAC-SHA512 on Apple GPU (one 64-byte output block per thread).
// Host prepends sha512_consts.h (K512, IV512) before compiling.
//
// keys:  16 big-endian words per thread = HMAC key zero-padded to 128 bytes
//        (keys longer than 128 bytes are pre-hashed with SHA-512 on the host).
// salt:  16 words = the whole second block of the first inner hash:
//        salt || INT(1) || 0x80 || 0.. || bitlen(128 + saltLen + 4).
// out:   8 big-endian words per thread = T1 = U1 ^ U2 ^ ... ^ U_iters.

#include <metal_stdlib>
using namespace metal;

#define ROTR(x, n) rotate((x), (ulong)(64 - (n)))
#define BS0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define BS1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SS0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define SS1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

#define RND(a, b, c, d, e, f, g, h, wv, i)                          \
    {                                                               \
        ulong t1 = h + BS1(e) + CH(e, f, g) + K512[i] + (wv);       \
        ulong t2 = BS0(a) + MAJ(a, b, c);                           \
        d += t1;                                                    \
        h = t1 + t2;                                                \
    }

#define EXP(i) (w[(i) & 15] += SS1(w[((i) - 2) & 15]) + w[((i) - 7) & 15] + SS0(w[((i) - 15) & 15]))

#define R8(i)                                   \
    RND(a, b, c, d, e, f, g, h, w[(i) + 0], (i) + 0) \
    RND(h, a, b, c, d, e, f, g, w[(i) + 1], (i) + 1) \
    RND(g, h, a, b, c, d, e, f, w[(i) + 2], (i) + 2) \
    RND(f, g, h, a, b, c, d, e, w[(i) + 3], (i) + 3) \
    RND(e, f, g, h, a, b, c, d, w[(i) + 4], (i) + 4) \
    RND(d, e, f, g, h, a, b, c, w[(i) + 5], (i) + 5) \
    RND(c, d, e, f, g, h, a, b, w[(i) + 6], (i) + 6) \
    RND(b, c, d, e, f, g, h, a, w[(i) + 7], (i) + 7)

#define R8X(i)                                   \
    RND(a, b, c, d, e, f, g, h, EXP((i) + 0), (i) + 0) \
    RND(h, a, b, c, d, e, f, g, EXP((i) + 1), (i) + 1) \
    RND(g, h, a, b, c, d, e, f, EXP((i) + 2), (i) + 2) \
    RND(f, g, h, a, b, c, d, e, EXP((i) + 3), (i) + 3) \
    RND(e, f, g, h, a, b, c, d, EXP((i) + 4), (i) + 4) \
    RND(d, e, f, g, h, a, b, c, EXP((i) + 5), (i) + 5) \
    RND(c, d, e, f, g, h, a, b, EXP((i) + 6), (i) + 6) \
    RND(b, c, d, e, f, g, h, a, EXP((i) + 7), (i) + 7)

// st = SHA-512 compression of block w starting from state st. w is clobbered.
static inline void compress(thread ulong *st, thread ulong *w) {
    ulong a = st[0], b = st[1], c = st[2], d = st[3];
    ulong e = st[4], f = st[5], g = st[6], h = st[7];
    R8(0) R8(8)
    R8X(16) R8X(24) R8X(32) R8X(40) R8X(48) R8X(56) R8X(64) R8X(72)
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// One HMAC step on a 64-byte message: out = H(opad || H(ipad || msg)).
static inline void hmac64(thread const ulong *ist, thread const ulong *ost,
                          thread ulong *msg /* in: 8 words, out: 8 words */) {
    ulong w[16];
    ulong s[8];
    for (int j = 0; j < 8; j++) { w[j] = msg[j]; s[j] = ist[j]; }
    w[8] = 0x8000000000000000UL;
    w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
    w[15] = (128 + 64) * 8;
    compress(s, w);
    for (int j = 0; j < 8; j++) { w[j] = s[j]; msg[j] = ost[j]; }
    w[8] = 0x8000000000000000UL;
    w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
    w[15] = (128 + 64) * 8;
    compress(msg, w);
}

kernel void pbkdf2_sha512(device const ulong *keys [[buffer(0)]],
                          constant ulong *salt [[buffer(1)]],
                          constant uint &iters [[buffer(2)]],
                          device ulong *out [[buffer(3)]],
                          uint gid [[thread_position_in_grid]]) {
    ulong ist[8], ost[8], w[16];

    // ipad / opad states
    for (int j = 0; j < 8; j++) { ist[j] = IV512[j]; ost[j] = IV512[j]; }
    for (int j = 0; j < 16; j++) w[j] = keys[gid * 16 + j] ^ 0x3636363636363636UL;
    compress(ist, w);
    for (int j = 0; j < 16; j++) w[j] = keys[gid * 16 + j] ^ 0x5c5c5c5c5c5c5c5cUL;
    compress(ost, w);

    // U1 = HMAC(key, salt || INT(1))
    ulong u[8];
    for (int j = 0; j < 8; j++) u[j] = ist[j];
    for (int j = 0; j < 16; j++) w[j] = salt[j];
    compress(u, w);
    {
        ulong s[8];
        for (int j = 0; j < 8; j++) { w[j] = u[j]; s[j] = ost[j]; }
        w[8] = 0x8000000000000000UL;
        w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
        w[15] = (128 + 64) * 8;
        compress(s, w);
        for (int j = 0; j < 8; j++) u[j] = s[j];
    }

    ulong t[8];
    for (int j = 0; j < 8; j++) t[j] = u[j];
    for (uint it = 1; it < iters; it++) {
        hmac64(ist, ost, u);
        for (int j = 0; j < 8; j++) t[j] ^= u[j];
    }
    for (int j = 0; j < 8; j++) out[gid * 8 + j] = t[j];
}

// ---------- chunked PBKDF2 (state kept in device memory between dispatches) ----------
// Lets 100 000-iteration TON derivations be split into short command buffers.
struct PState { ulong ist[8]; ulong ost[8]; ulong u[8]; ulong t[8]; };

kernel void pbkdf2_init(device const ulong *keys [[buffer(0)]],
                        constant ulong *salt [[buffer(1)]],
                        device PState *st [[buffer(2)]],
                        constant uint &n [[buffer(3)]],
                        uint gid [[thread_position_in_grid]]) {
    if (gid >= n) return;
    ulong ist[8], ost[8], w[16], u[8];
    for (int j = 0; j < 8; j++) { ist[j] = IV512[j]; ost[j] = IV512[j]; }
    for (int j = 0; j < 16; j++) w[j] = keys[gid * 16 + j] ^ 0x3636363636363636UL;
    compress(ist, w);
    for (int j = 0; j < 16; j++) w[j] = keys[gid * 16 + j] ^ 0x5c5c5c5c5c5c5c5cUL;
    compress(ost, w);
    for (int j = 0; j < 8; j++) u[j] = ist[j];
    for (int j = 0; j < 16; j++) w[j] = salt[j];
    compress(u, w);
    ulong s[8];
    for (int j = 0; j < 8; j++) { w[j] = u[j]; s[j] = ost[j]; }
    w[8] = 0x8000000000000000UL;
    w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
    w[15] = (128 + 64) * 8;
    compress(s, w);
    for (int j = 0; j < 8; j++) {
        st[gid].ist[j] = ist[j]; st[gid].ost[j] = ost[j];
        st[gid].u[j] = s[j];     st[gid].t[j] = s[j];
    }
}

kernel void pbkdf2_iter(device PState *st [[buffer(0)]],
                        constant uint &iters [[buffer(1)]],
                        constant uint &n [[buffer(2)]],
                        uint gid [[thread_position_in_grid]]) {
    if (gid >= n) return;
    ulong ist[8], ost[8], u[8], t[8];
    for (int j = 0; j < 8; j++) {
        ist[j] = st[gid].ist[j]; ost[j] = st[gid].ost[j];
        u[j] = st[gid].u[j];     t[j] = st[gid].t[j];
    }
    for (uint it = 0; it < iters; it++) {
        hmac64(ist, ost, u);
        for (int j = 0; j < 8; j++) t[j] ^= u[j];
    }
    for (int j = 0; j < 8; j++) { st[gid].u[j] = u[j]; st[gid].t[j] = t[j]; }
}
