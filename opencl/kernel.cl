// seedvanity OpenCL kernels (OpenCL C 1.2): PBKDF2-HMAC-SHA512 and SLIP-10 ed25519 derivation.
// Port of gpu/pbkdf2.metal. The host prepends sha512_consts.h (K512, IV512).
//
// keys:  16 big-endian words per thread = HMAC key zero-padded to 128 bytes
//        (longer keys are pre-hashed with SHA-512 on the host).
// salt:  16 words = the whole second block of the first inner hash:
//        salt || INT(1) || 0x80 || 0.. || bitlen(128 + saltLen + 4).
// state: PBKDF2 state per thread, kept between dispatches so long derivations can be split into
//        short kernels (Windows resets the GPU driver after ~2 s in one kernel).

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
void compress(ulong *st, ulong *w) {
    ulong a = st[0], b = st[1], c = st[2], d = st[3];
    ulong e = st[4], f = st[5], g = st[6], h = st[7];
    R8(0) R8(8)
    R8X(16) R8X(24) R8X(32) R8X(40) R8X(48) R8X(56) R8X(64) R8X(72)
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// Padding words for a 64-byte message after a 128-byte key block: 0x80, zeros, bitlen 1536.
void pad64(ulong *w) {
    w[8] = 0x8000000000000000UL;
    w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0; w[14] = 0;
    w[15] = (128 + 64) * 8;
}

// msg (8 words) = HMAC(key, msg) given the key's ipad/opad states.
void hmac64(const ulong *ist, const ulong *ost, ulong *msg) {
    ulong w[16], s[8];
    for (int j = 0; j < 8; j++) { w[j] = msg[j]; s[j] = ist[j]; }
    pad64(w);
    compress(s, w);
    for (int j = 0; j < 8; j++) { w[j] = s[j]; msg[j] = ost[j]; }
    pad64(w);
    compress(msg, w);
}

// ipad / opad states of an HMAC key given as a 128-byte block (16 words)
void hmac_keys(const ulong *kb, ulong *ist, ulong *ost) {
    ulong w[16];
    for (int j = 0; j < 8; j++) { ist[j] = IV512[j]; ost[j] = IV512[j]; }
    for (int j = 0; j < 16; j++) w[j] = kb[j] ^ 0x3636363636363636UL;
    compress(ist, w);
    for (int j = 0; j < 16; j++) w[j] = kb[j] ^ 0x5c5c5c5c5c5c5c5cUL;
    compress(ost, w);
}

typedef struct { ulong ist[8]; ulong ost[8]; ulong u[8]; ulong t[8]; } PState;

__kernel void pbkdf2_init(__global const ulong *keys, __constant ulong *salt,
                          __global PState *st, uint n) {
    uint gid = get_global_id(0);
    if (gid >= n) return;
    ulong kb[16], ist[8], ost[8], w[16], u[8];
    for (int j = 0; j < 16; j++) kb[j] = keys[gid * 16 + j];
    hmac_keys(kb, ist, ost);
    // U1 = HMAC(key, salt || INT(1))
    for (int j = 0; j < 8; j++) u[j] = ist[j];
    for (int j = 0; j < 16; j++) w[j] = salt[j];
    compress(u, w);
    ulong s[8];
    for (int j = 0; j < 8; j++) { w[j] = u[j]; s[j] = ost[j]; }
    pad64(w);
    compress(s, w);
    for (int j = 0; j < 8; j++) {
        st[gid].ist[j] = ist[j]; st[gid].ost[j] = ost[j];
        st[gid].u[j] = s[j];     st[gid].t[j] = s[j];
    }
}

__kernel void pbkdf2_iter(__global PState *st, uint iters, uint n) {
    uint gid = get_global_id(0);
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

// SLIP-0010 ed25519, path m/44'/607'/0', from the 64-byte BIP39 seed in st[gid].t.
// mkey: ipad/opad states of the constant key "ed25519 seed" (16 words, computed on the host).
// out: 4 big-endian words per thread = the ed25519 private key seed.
__kernel void slip10(__global const PState *st, __constant ulong *mkey, __global ulong *out, uint n) {
    uint gid = get_global_id(0);
    if (gid >= n) return;
    ulong w[16], s[8], I[8];
    // master: I = HMAC-SHA512("ed25519 seed", seed)
    for (int j = 0; j < 8; j++) { w[j] = st[gid].t[j]; s[j] = mkey[j]; }
    pad64(w);
    compress(s, w);
    for (int j = 0; j < 8; j++) { w[j] = s[j]; I[j] = mkey[8 + j]; }
    pad64(w);
    compress(I, w);
    // hardened children: I = HMAC-SHA512(c, 0x00 || k || ser32(index | 2^31))
    const uint path[3] = {44u, 607u, 0u};
    for (int level = 0; level < 3; level++) {
        ulong kb[16], ist[8], ost[8];
        for (int j = 0; j < 4; j++) kb[j] = I[4 + j]; // chain code
        for (int j = 4; j < 16; j++) kb[j] = 0;
        hmac_keys(kb, ist, ost);
        ulong idx = (ulong)(path[level] | 0x80000000u);
        // 37-byte message: 0x00, k (32 bytes), index (4 bytes); then 0x80 and bitlen (128 + 37) * 8
        w[0] = I[0] >> 8;
        w[1] = (I[0] << 56) | (I[1] >> 8);
        w[2] = (I[1] << 56) | (I[2] >> 8);
        w[3] = (I[2] << 56) | (I[3] >> 8);
        w[4] = (I[3] << 56) | (idx << 24) | (0x80UL << 16);
        for (int j = 5; j < 15; j++) w[j] = 0;
        w[15] = (128 + 37) * 8;
        for (int j = 0; j < 8; j++) s[j] = ist[j];
        compress(s, w);
        for (int j = 0; j < 8; j++) { w[j] = s[j]; I[j] = ost[j]; }
        pad64(w);
        compress(I, w);
    }
    for (int j = 0; j < 4; j++) out[gid * 4 + j] = I[j];
}
