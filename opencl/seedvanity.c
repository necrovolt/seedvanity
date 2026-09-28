// seedvanity (OpenCL): finds a seed phrase whose TON W5 (v5r1) wallet address ends with a pattern.
//
// Platforms: Linux and Windows with any OpenCL GPU (NVIDIA, AMD, Intel); builds on macOS for testing.
// GPU: PBKDF2-HMAC-SHA512 (+ SLIP-10 m/44'/607'/0' for BIP39) in kernel.cl.
// CPU: Ed25519 public key (Monocypher), W5 address, pattern check, in parallel threads.
//
// Wallet: W5 = v5r1, mainnet (network id -239), workchain 0, subwallet 0: the address Tonkeeper and
// My Wallet show for W5. Seed phrases are written only to the results file, never to stdout.
// Every hit is re-derived on the CPU and by two independent libraries (@ton/ton, tonutils-go).

#if !defined(_WIN32) && !defined(__APPLE__)
#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#endif
#define CL_TARGET_OPENCL_VERSION 120
#define CL_SILENCE_DEPRECATION

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#define popen _popen
#define pclose _pclose
#define PATH_SEP '\\'
#else
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEP '/'
#endif
#ifdef __linux__
#include <sys/random.h>
#endif
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#include <mach-o/dyld.h>
#else
#include <CL/cl.h>
#endif

#include "embedded.h"
#include "sha256.h"
#include "third_party/monocypher/monocypher-ed25519.h"
#include "third_party/monocypher/monocypher.h"

// ---------------------------------------------------------------- utilities

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static double now_sec(void) {
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
#endif
}

static void clock_str(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, n, "%H:%M:%S", &tmv);
}

// Cryptographically secure randomness from the operating system.
static void random_bytes(uint8_t *p, size_t n) {
#if defined(_WIN32)
    while (n) {
        ULONG c = n > 0x10000000 ? 0x10000000 : (ULONG)n;
        if (BCryptGenRandom(NULL, p, c, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) die("BCryptGenRandom failed");
        p += c;
        n -= c;
    }
#elif defined(__APPLE__)
    arc4random_buf(p, n);
#else
    while (n) {
        ssize_t r = getrandom(p, n > 33554431 ? 33554431 : n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            die("getrandom failed");
        }
        p += r;
        n -= (size_t)r;
    }
#endif
}

static int cpu_count(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long c = sysconf(_SC_NPROCESSORS_ONLN);
    return c > 0 ? (int)c : 4;
#endif
}

// Directory that contains the executable (the tool lives in <root>/opencl/).
static void exe_dir(char *out, size_t n) {
    char p[4096] = {0};
#if defined(_WIN32)
    GetModuleFileNameA(NULL, p, sizeof p - 1);
#elif defined(__APPLE__)
    uint32_t sz = sizeof p;
    char raw[4096];
    if (_NSGetExecutablePath(raw, &sz) != 0 || !realpath(raw, p)) strcpy(p, "./x");
#else
    ssize_t r = readlink("/proc/self/exe", p, sizeof p - 1);
    if (r <= 0) strcpy(p, "./x");
#endif
    char *s = strrchr(p, PATH_SEP);
    if (s) *s = 0; else strcpy(p, ".");
    snprintf(out, n, "%s", p);
}

// ---------------------------------------------------------------- threads

typedef struct { void (*fn)(void *, int, int); void *ctx; int tid, nt; } TArg;
#ifdef _WIN32
typedef CRITICAL_SECTION mutex_t;
static void mutex_init(mutex_t *m) { InitializeCriticalSection(m); }
static void mutex_lock(mutex_t *m) { EnterCriticalSection(m); }
static void mutex_unlock(mutex_t *m) { LeaveCriticalSection(m); }
static unsigned __stdcall thunk(void *p) { TArg *a = (TArg *)p; a->fn(a->ctx, a->tid, a->nt); return 0; }
#else
typedef pthread_mutex_t mutex_t;
static void mutex_init(mutex_t *m) { pthread_mutex_init(m, NULL); }
static void mutex_lock(mutex_t *m) { pthread_mutex_lock(m); }
static void mutex_unlock(mutex_t *m) { pthread_mutex_unlock(m); }
static void *thunk(void *p) { TArg *a = (TArg *)p; a->fn(a->ctx, a->tid, a->nt); return NULL; }
#endif

// Runs fn(ctx, tid, nt) on nt threads and waits for all of them.
static void parallel(int nt, void (*fn)(void *, int, int), void *ctx) {
    if (nt <= 1) { fn(ctx, 0, 1); return; }
    TArg *args = calloc((size_t)nt, sizeof *args);
#ifdef _WIN32
    HANDLE *h = calloc((size_t)nt, sizeof *h);
#else
    pthread_t *h = calloc((size_t)nt, sizeof *h);
#endif
    if (!args || !h) die("out of memory");
    for (int i = 0; i < nt; i++) {
        args[i] = (TArg){fn, ctx, i, nt};
#ifdef _WIN32
        h[i] = (HANDLE)_beginthreadex(NULL, 0, thunk, &args[i], 0, NULL);
        if (!h[i]) die("thread start failed");
#else
        if (pthread_create(&h[i], NULL, thunk, &args[i]) != 0) die("thread start failed");
#endif
    }
    for (int i = 0; i < nt; i++) {
#ifdef _WIN32
        WaitForSingleObject(h[i], INFINITE);
        CloseHandle(h[i]);
#else
        pthread_join(h[i], NULL);
#endif
    }
    free(args);
    free(h);
}

// ---------------------------------------------------------------- options

enum { BIP12, BIP24, TON24 };
static const char *MODE_NAME[] = {"bip39-12", "bip39-24", "ton-24"};

static struct {
    char suffix[128];
    int mode, bounceable, ignore_case, threads, count, verify, device, list_devices;
    char out[4096], dump_file[4096];
    double bench;
    int dump;
} opt;

static char root_dir[4096];
static uint8_t pattern[16][256]; // pattern[k][c]: byte c allowed at position k of the ending
static int pattern_len;

static void usage(int code) {
    printf("usage: seedvanity --suffix '[a-z_]HELLO' [--mode bip39-12|bip39-24|ton-24] [--form uq|eq]\n"
           "                 [--ignore-case] [--threads N] [--count N] [--out FILE] [--bench SEC]\n"
           "                 [--device N] [--list-devices]\n"
           "  --suffix       ending; [..] = one of the listed characters, ranges allowed\n"
           "  --form uq      non-bounceable form UQ... (what wallets show for W5), default\n"
           "  --threads N    CPU threads for Ed25519 and addresses (default: all logical CPUs)\n"
           "  --count N      stop after N verified hits (default 1)\n"
           "  --device N     OpenCL GPU to use (see --list-devices), default 0\n");
    exit(code);
}

static int is_b64(int c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static void allow(uint8_t *set, int c) {
    if (!is_b64(c)) die("pattern may contain only A-Z a-z 0-9 - _ and [...] classes");
    set[c] = 1;
    if (opt.ignore_case && ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) set[c ^ 0x20] = 1;
}

static void parse_pattern(const char *s) {
    size_t i = 0, n = strlen(s);
    while (i < n) {
        if (pattern_len >= 10) die("pattern longer than 10 characters is hopeless");
        uint8_t *set = pattern[pattern_len];
        memset(set, 0, 256);
        if (s[i] == '[') {
            const char *close = strchr(s + i, ']');
            if (!close || close == s + i + 1) die("unclosed [ in pattern");
            size_t j = i + 1, end = (size_t)(close - s);
            while (j < end) {
                if (j + 2 < end && s[j + 1] == '-') {
                    if ((unsigned char)s[j] > (unsigned char)s[j + 2]) die("bad range in pattern");
                    for (int c = (unsigned char)s[j]; c <= (unsigned char)s[j + 2]; c++)
                        if (is_b64(c)) allow(set, c);
                    j += 3;
                } else {
                    allow(set, (unsigned char)s[j]);
                    j++;
                }
            }
            i = end + 1;
        } else {
            allow(set, (unsigned char)s[i]);
            i++;
        }
        pattern_len++;
    }
}

static double expected_tries(void) {
    double e = 1;
    for (int k = 0; k < pattern_len; k++) {
        int c = 0;
        for (int b = 0; b < 256; b++) c += pattern[k][b];
        e *= 64.0 / c;
    }
    return e;
}

// ---------------------------------------------------------------- crypto helpers

static const uint8_t SALT_MNEMONIC[] = "mnemonic";
static const uint8_t SALT_TON_VERSION[] = "TON seed version";
static const uint8_t SALT_TON_DEFAULT[] = "TON default seed";
#define TON_BASIC_ITERS 390 // max(1, 100000 / 256)
#define TON_ITERS 100000

static void hmac512(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[64]) {
    crypto_sha512_hmac(out, key, klen, msg, mlen);
}

// Reference PBKDF2-HMAC-SHA512 on the CPU (one 64-byte block): self-test and hit re-derivation.
static void cpu_pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t iters, uint8_t out[64]) {
    crypto_sha512_hmac_ctx base, c;
    uint8_t u[64], blk[128];
    crypto_sha512_hmac_init(&base, pw, pwlen);
    memcpy(blk, salt, slen);
    blk[slen] = 0; blk[slen + 1] = 0; blk[slen + 2] = 0; blk[slen + 3] = 1;
    c = base;
    crypto_sha512_hmac_update(&c, blk, slen + 4);
    crypto_sha512_hmac_final(&c, u);
    memcpy(out, u, 64);
    for (uint32_t it = 1; it < iters; it++) {
        c = base;
        crypto_sha512_hmac_update(&c, u, 64);
        crypto_sha512_hmac_final(&c, u);
        for (int j = 0; j < 64; j++) out[j] ^= u[j];
    }
}

// SLIP-0010 ed25519, path m/44'/607'/0'
static void cpu_slip10(const uint8_t seed[64], uint8_t out[32]) {
    uint8_t I[64], data[37];
    hmac512((const uint8_t *)"ed25519 seed", 12, seed, 64, I);
    const uint32_t path[3] = {44, 607, 0};
    for (int l = 0; l < 3; l++) {
        uint32_t i = path[l] | 0x80000000u;
        data[0] = 0;
        memcpy(data + 1, I, 32);
        data[33] = (uint8_t)(i >> 24); data[34] = (uint8_t)(i >> 16); data[35] = (uint8_t)(i >> 8); data[36] = (uint8_t)i;
        uint8_t c[32];
        memcpy(c, I + 32, 32);
        hmac512(c, 32, data, 37, I);
    }
    memcpy(out, I, 32);
}

static void ed25519_public(const uint8_t priv[32], uint8_t pub[32]) {
    uint8_t sk[64], seed[32];
    memcpy(seed, priv, 32); // Monocypher wipes the seed argument
    crypto_ed25519_key_pair(sk, pub, seed);
    crypto_wipe(sk, 64);
}

// 11-bit word indices from a bit string
static void indices11(const uint8_t *b, int count, int *out) {
    uint32_t acc = 0;
    int nbits = 0, pos = 0;
    for (int k = 0; k < count; k++) {
        while (nbits < 11) { acc = (acc << 8) | b[pos++]; nbits += 8; }
        out[k] = (int)((acc >> (nbits - 11)) & 0x7FF);
        nbits -= 11;
        acc &= (1u << nbits) - 1;
    }
}

static void bip39_indices(const uint8_t *ent, int entlen, int *out) {
    uint8_t buf[33], h[32];
    memcpy(buf, ent, (size_t)entlen);
    sha256(ent, (size_t)entlen, h);
    buf[entlen] = h[0];
    indices11(buf, entlen * 3 / 4, out);
}

// BIP39 checksum validity of an arbitrary 12- or 24-word sequence
static int bip39_valid(const int *idx, int nw) {
    if (nw != 12 && nw != 24) return 0;
    uint8_t bits[33] = {0};
    int nb = 0;
    for (int k = 0; k < nw; k++)
        for (int b = 10; b >= 0; b--, nb++)
            if ((idx[k] >> b) & 1) bits[nb / 8] |= (uint8_t)(0x80 >> (nb % 8));
    int entbits = nw * 11 * 32 / 33, csbits = nw * 11 - entbits;
    uint8_t h[32];
    sha256(bits, (size_t)entbits / 8, h);
    for (int k = 0; k < csbits; k++) {
        int got = (bits[(entbits + k) / 8] >> (7 - (entbits + k) % 8)) & 1;
        if (got != ((h[0] >> (7 - k)) & 1)) return 0;
    }
    return 1;
}

static size_t phrase_bytes(const int *idx, int nw, char *out) {
    size_t n = 0;
    for (int k = 0; k < nw; k++) {
        if (k) out[n++] = ' ';
        size_t l = strlen(WORDS[idx[k]]);
        memcpy(out + n, WORDS[idx[k]], l);
        n += l;
    }
    out[n] = 0;
    return n;
}

static void ton_entropy(const char *phrase, size_t len, uint8_t out[64]) {
    hmac512((const uint8_t *)phrase, len, NULL, 0, out);
}

// TON standard validity (what @ton/crypto mnemonicValidate checks, without a password)
static int ton_valid(const char *phrase, size_t len) {
    uint8_t e[64], s[64];
    ton_entropy(phrase, len, e);
    cpu_pbkdf2(e, 64, SALT_TON_VERSION, 16, TON_BASIC_ITERS, s);
    return s[0] == 0;
}

// HMAC key zero-padded to one 128-byte block as 16 big-endian words (long keys pre-hashed)
static void key_block(const uint8_t *pw, size_t len, uint64_t *w) {
    uint8_t k[128] = {0};
    if (len > 128) { crypto_sha512(k, pw, len); } else memcpy(k, pw, len);
    for (int j = 0; j < 16; j++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v = (v << 8) | k[j * 8 + b];
        w[j] = v;
    }
}

static void salt_block(const uint8_t *salt, size_t slen, uint64_t *w) {
    uint8_t b[128] = {0};
    memcpy(b, salt, slen);
    b[slen + 3] = 1;
    b[slen + 4] = 0x80;
    uint64_t bits = (uint64_t)(128 + slen + 4) * 8;
    for (int j = 0; j < 8; j++) b[120 + j] = (uint8_t)(bits >> (56 - 8 * j));
    for (int j = 0; j < 16; j++) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | b[j * 8 + k];
        w[j] = v;
    }
}

// ---------------------------------------------------------------- W5 (v5r1) address

// Code cell of wallet v5r1 (as in @ton/ton WalletContractV5R1, tonutils-go ConfigV5R1Final)
static const uint8_t W5_CODE_HASH[32] = {
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f};
#define W5_CODE_DEPTH 6
// wallet_id = network_global_id (-239) XOR context{client=1, workchain=0, version=v5r1(0), subwallet=0}
#define W5_WALLET_ID (0xFFFFFF11u ^ 0x80000000u) // 2147483409

// State-init hash of W5 for a public key = the account id
static void w5_account_id(const uint8_t pub[32], uint8_t id[32]) {
    // data cell, 322 bits: is_signature_allowed=1 | seqno:32=0 | wallet_id:32 | public_key:256 | extensions=0
    uint8_t d[2 + 41] = {0}, y[36], dh[32], si[71];
    d[0] = 0x00; // refs 0, level 0
    d[1] = 81;   // floor(322/8) + ceil(322/8)
    d[2] = 0x80;
    y[0] = (uint8_t)(W5_WALLET_ID >> 24); y[1] = (uint8_t)(W5_WALLET_ID >> 16);
    y[2] = (uint8_t)(W5_WALLET_ID >> 8); y[3] = (uint8_t)W5_WALLET_ID;
    memcpy(y + 4, pub, 32);
    uint8_t prev = 0;
    for (int k = 0; k < 36; k++) { d[2 + 4 + k] = (uint8_t)((prev << 7) | (y[k] >> 1)); prev = y[k]; }
    d[2 + 40] = (uint8_t)((prev << 7) | 0x20); // last pubkey bit, extensions bit 0, completion tag
    sha256(d, sizeof d, dh);
    // StateInit: split_depth 0, special 0, code 1, data 1, library 0 -> 0x34; 2 refs
    si[0] = 0x02; si[1] = 0x01; si[2] = 0x34;
    si[3] = 0; si[4] = W5_CODE_DEPTH; si[5] = 0; si[6] = 0;
    memcpy(si + 7, W5_CODE_HASH, 32);
    memcpy(si + 39, dh, 32);
    sha256(si, sizeof si, id);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void friendly(const uint8_t id[32], int bounceable, char out[49]) {
    uint8_t b[36];
    b[0] = bounceable ? 0x11 : 0x51;
    b[1] = 0x00;
    memcpy(b + 2, id, 32);
    uint16_t crc = 0;
    for (int i = 0; i < 34; i++) {
        crc ^= (uint16_t)(b[i] << 8);
        for (int k = 0; k < 8; k++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    b[34] = (uint8_t)(crc >> 8);
    b[35] = (uint8_t)crc;
    for (int i = 0, o = 0; i < 36; i += 3) {
        uint32_t v = (uint32_t)b[i] << 16 | (uint32_t)b[i + 1] << 8 | b[i + 2];
        out[o++] = B64[v >> 18]; out[o++] = B64[(v >> 12) & 63]; out[o++] = B64[(v >> 6) & 63]; out[o++] = B64[v & 63];
    }
    out[48] = 0;
}

static int matches(const char addr[49]) {
    int off = 48 - pattern_len;
    for (int k = pattern_len - 1; k >= 0; k--)
        if (!pattern[k][(unsigned char)addr[off + k]]) return 0;
    return 1;
}

static void hexs(const uint8_t *b, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

// ---------------------------------------------------------------- GPU (OpenCL)

#define CK(x) do { cl_int e_ = (x); if (e_ != CL_SUCCESS) die("OpenCL error %d at line %d: %s", e_, __LINE__, #x); } while (0)

static struct {
    cl_device_id dev;
    cl_context ctx;
    cl_command_queue q;
    cl_program prog;
    cl_kernel kinit, kiter, kslip;
    cl_mem salt_mnemonic, salt_ton_version, salt_ton_default, mkey;
    char name[256];
    size_t local;
} gpu;

static int list_gpus(cl_device_id *devs, int max) {
    cl_platform_id plats[16];
    cl_uint np = 0;
    if (clGetPlatformIDs(16, plats, &np) != CL_SUCCESS) return 0;
    int n = 0;
    for (cl_uint p = 0; p < np && n < max; p++) {
        cl_uint nd = 0;
        if (clGetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, (cl_uint)(max - n), devs + n, &nd) == CL_SUCCESS) n += (int)nd;
    }
    return n;
}

static cl_mem const_buffer(const void *data, size_t size) {
    cl_int e;
    cl_mem m = clCreateBuffer(gpu.ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, size, (void *)data, &e);
    CK(e);
    return m;
}

static void gpu_init(void) {
    cl_device_id devs[32];
    int n = list_gpus(devs, 32);
    if (opt.list_devices) {
        for (int i = 0; i < n; i++) {
            char name[256] = {0}, ver[128] = {0};
            cl_uint cu = 0;
            clGetDeviceInfo(devs[i], CL_DEVICE_NAME, sizeof name, name, NULL);
            clGetDeviceInfo(devs[i], CL_DEVICE_VERSION, sizeof ver, ver, NULL);
            clGetDeviceInfo(devs[i], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof cu, &cu, NULL);
            printf("[%d] %s, %u compute units, %s\n", i, name, cu, ver);
        }
        if (!n) printf("no OpenCL GPU found (is the GPU driver with OpenCL support installed?)\n");
        exit(0);
    }
    if (!n) die("no OpenCL GPU found: install the GPU driver with OpenCL support (see README)");
    if (opt.device < 0 || opt.device >= n) die("--device %d: only %d GPU(s), see --list-devices", opt.device, n);
    gpu.dev = devs[opt.device];
    clGetDeviceInfo(gpu.dev, CL_DEVICE_NAME, sizeof gpu.name, gpu.name, NULL);
    cl_int e;
    gpu.ctx = clCreateContext(NULL, 1, &gpu.dev, NULL, NULL, &e);
    CK(e);
    gpu.q = clCreateCommandQueue(gpu.ctx, gpu.dev, CL_QUEUE_PROFILING_ENABLE, &e);
    CK(e);
    gpu.prog = clCreateProgramWithSource(gpu.ctx, (cl_uint)KERNEL_SRC_LINES, (const char **)KERNEL_SRC, NULL, &e);
    CK(e);
    if (clBuildProgram(gpu.prog, 1, &gpu.dev, "-cl-std=CL1.2", NULL, NULL) != CL_SUCCESS) {
        size_t len = 0;
        clGetProgramBuildInfo(gpu.prog, gpu.dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
        char *log = malloc(len + 1);
        clGetProgramBuildInfo(gpu.prog, gpu.dev, CL_PROGRAM_BUILD_LOG, len, log, NULL);
        log[len] = 0;
        die("OpenCL kernel build failed:\n%s", log);
    }
    gpu.kinit = clCreateKernel(gpu.prog, "pbkdf2_init", &e); CK(e);
    gpu.kiter = clCreateKernel(gpu.prog, "pbkdf2_iter", &e); CK(e);
    gpu.kslip = clCreateKernel(gpu.prog, "slip10", &e); CK(e);
    size_t wg = 64, maxwg = 0;
    clGetKernelWorkGroupInfo(gpu.kiter, gpu.dev, CL_KERNEL_WORK_GROUP_SIZE, sizeof maxwg, &maxwg, NULL);
    gpu.local = maxwg && maxwg < wg ? maxwg : wg;
    uint64_t w[16];
    salt_block(SALT_MNEMONIC, 8, w);     gpu.salt_mnemonic = const_buffer(w, 128);
    salt_block(SALT_TON_VERSION, 16, w); gpu.salt_ton_version = const_buffer(w, 128);
    salt_block(SALT_TON_DEFAULT, 16, w); gpu.salt_ton_default = const_buffer(w, 128);
    gpu.mkey = NULL; // set by make_mkey()
}

static size_t round_up(size_t n) { return (n + gpu.local - 1) / gpu.local * gpu.local; }

// Adaptive PBKDF2 chunk: iterations per kernel launch, tuned to keep each launch ~0.25 s.
static uint32_t chunk_iters = 64; // until measured: 16384 threads x 64 iterations is short even on weak GPUs

typedef struct {
    cl_mem keys, state, out;
    uint32_t n;
    cl_event ev;
    cl_event kev;    // one pbkdf2_iter launch, profiled to tune chunk_iters
    uint32_t kiters; // iterations in that launch
} Job;

static void job_release(Job *j) {
    if (j->keys) clReleaseMemObject(j->keys);
    if (j->state) clReleaseMemObject(j->state);
    if (j->out) clReleaseMemObject(j->out);
    if (j->ev) clReleaseEvent(j->ev);
    if (j->kev) clReleaseEvent(j->kev);
    memset(j, 0, sizeof *j);
}

// Enqueues PBKDF2 over n key blocks; with slip10 != 0 also SLIP-10 (out = 4 words per thread),
// otherwise out = the first out_words words of the PBKDF2 output. Reads out into host asynchronously.
static void job_submit(Job *j, const uint64_t *keys, uint32_t n, cl_mem salt, uint32_t iters, int slip10,
                       uint32_t out_words, uint64_t *host_out) {
    cl_int e;
    memset(j, 0, sizeof *j);
    j->n = n;
    j->keys = clCreateBuffer(gpu.ctx, CL_MEM_READ_ONLY, (size_t)n * 128, NULL, &e); CK(e);
    j->state = clCreateBuffer(gpu.ctx, CL_MEM_READ_WRITE, (size_t)n * 256, NULL, &e); CK(e);
    CK(clEnqueueWriteBuffer(gpu.q, j->keys, CL_FALSE, 0, (size_t)n * 128, keys, 0, NULL, NULL));
    size_t g = round_up(n);
    CK(clSetKernelArg(gpu.kinit, 0, sizeof(cl_mem), &j->keys));
    CK(clSetKernelArg(gpu.kinit, 1, sizeof(cl_mem), &salt));
    CK(clSetKernelArg(gpu.kinit, 2, sizeof(cl_mem), &j->state));
    CK(clSetKernelArg(gpu.kinit, 3, sizeof(cl_uint), &n));
    CK(clEnqueueNDRangeKernel(gpu.q, gpu.kinit, 1, NULL, &g, &gpu.local, 0, NULL, NULL));
    for (uint32_t done = 1; done < iters;) {
        uint32_t k = iters - done < chunk_iters ? iters - done : chunk_iters;
        CK(clSetKernelArg(gpu.kiter, 0, sizeof(cl_mem), &j->state));
        CK(clSetKernelArg(gpu.kiter, 1, sizeof(cl_uint), &k));
        CK(clSetKernelArg(gpu.kiter, 2, sizeof(cl_uint), &n));
        int profile = !j->kev && (done + k >= iters || done > 1); // the second launch, or the only one
        CK(clEnqueueNDRangeKernel(gpu.q, gpu.kiter, 1, NULL, &g, &gpu.local, 0, NULL, profile ? &j->kev : NULL));
        if (profile) j->kiters = k;
        CK(clFlush(gpu.q));
        done += k;
    }
    if (slip10) {
        j->out = clCreateBuffer(gpu.ctx, CL_MEM_WRITE_ONLY, (size_t)n * 32, NULL, &e); CK(e);
        CK(clSetKernelArg(gpu.kslip, 0, sizeof(cl_mem), &j->state));
        CK(clSetKernelArg(gpu.kslip, 1, sizeof(cl_mem), &gpu.mkey));
        CK(clSetKernelArg(gpu.kslip, 2, sizeof(cl_mem), &j->out));
        CK(clSetKernelArg(gpu.kslip, 3, sizeof(cl_uint), &n));
        CK(clEnqueueNDRangeKernel(gpu.q, gpu.kslip, 1, NULL, &g, &gpu.local, 0, NULL, NULL));
        CK(clEnqueueReadBuffer(gpu.q, j->out, CL_FALSE, 0, (size_t)n * 32, host_out, 0, NULL, &j->ev));
    } else {
        // t starts at word 24 of each 32-word PState; read it with a rectangular copy
        size_t origin[3] = {24 * 8, 0, 0}, horigin[3] = {0, 0, 0}, region[3] = {(size_t)out_words * 8, n, 1};
        CK(clEnqueueReadBufferRect(gpu.q, j->state, CL_FALSE, origin, horigin, region, 256, 0,
                                   (size_t)out_words * 8, 0, host_out, 0, NULL, &j->ev));
    }
    CK(clFlush(gpu.q));
}

// Measured GPU time of one pbkdf2_iter launch per iteration and thread batch (seconds), or 0.
static double last_iter_time;

static void job_wait(Job *j) {
    CK(clWaitForEvents(1, &j->ev));
    last_iter_time = 0;
    if (j->kev && j->kiters) {
        cl_ulong t0 = 0, t1 = 0;
        if (clGetEventProfilingInfo(j->kev, CL_PROFILING_COMMAND_START, sizeof t0, &t0, NULL) == CL_SUCCESS &&
            clGetEventProfilingInfo(j->kev, CL_PROFILING_COMMAND_END, sizeof t1, &t1, NULL) == CL_SUCCESS && t1 > t0)
            last_iter_time = (double)(t1 - t0) / 1e9 / j->kiters;
    }
}

// Kernel length control. Each pbkdf2_iter launch should take ~0.25 s: Windows resets the GPU driver
// after ~2 s in one kernel. The per-iteration cost is estimated conservatively as the larger of the
// profiled kernel time and the wall time of the whole loop (some drivers report wrong profiling
// times, Apple's among them), and it only decays slowly, so launches can only get shorter than planned.
static double iter_cost; // seconds per PBKDF2 iteration per thread

static void tune_chunk(uint32_t iters, uint32_t n, double loop_time) {
    double est = loop_time > 0 ? loop_time / ((double)iters * n) : 0;
    if (last_iter_time > 0) {
        double prof = last_iter_time / n;
        if (prof > est) est = prof;
    }
    if (est <= 0) return;
    iter_cost = est > iter_cost * 0.8 ? est : iter_cost * 0.8;
    double c = 0.25 / (iter_cost * n);
    chunk_iters = (uint32_t)(c < 8 ? 8 : c > 4096 ? 4096 : c);
}

// SHA-512 compression on the CPU, used once: the ipad/opad states of the constant SLIP-10 master key
// "ed25519 seed" (Monocypher does not expose intermediate SHA-512 states).
static const uint64_t K512C[80] = {
#define X(v) v##ULL
    X(0x428a2f98d728ae22), X(0x7137449123ef65cd), X(0xb5c0fbcfec4d3b2f), X(0xe9b5dba58189dbbc), X(0x3956c25bf348b538),
    X(0x59f111f1b605d019), X(0x923f82a4af194f9b), X(0xab1c5ed5da6d8118), X(0xd807aa98a3030242), X(0x12835b0145706fbe),
    X(0x243185be4ee4b28c), X(0x550c7dc3d5ffb4e2), X(0x72be5d74f27b896f), X(0x80deb1fe3b1696b1), X(0x9bdc06a725c71235),
    X(0xc19bf174cf692694), X(0xe49b69c19ef14ad2), X(0xefbe4786384f25e3), X(0x0fc19dc68b8cd5b5), X(0x240ca1cc77ac9c65),
    X(0x2de92c6f592b0275), X(0x4a7484aa6ea6e483), X(0x5cb0a9dcbd41fbd4), X(0x76f988da831153b5), X(0x983e5152ee66dfab),
    X(0xa831c66d2db43210), X(0xb00327c898fb213f), X(0xbf597fc7beef0ee4), X(0xc6e00bf33da88fc2), X(0xd5a79147930aa725),
    X(0x06ca6351e003826f), X(0x142929670a0e6e70), X(0x27b70a8546d22ffc), X(0x2e1b21385c26c926), X(0x4d2c6dfc5ac42aed),
    X(0x53380d139d95b3df), X(0x650a73548baf63de), X(0x766a0abb3c77b2a8), X(0x81c2c92e47edaee6), X(0x92722c851482353b),
    X(0xa2bfe8a14cf10364), X(0xa81a664bbc423001), X(0xc24b8b70d0f89791), X(0xc76c51a30654be30), X(0xd192e819d6ef5218),
    X(0xd69906245565a910), X(0xf40e35855771202a), X(0x106aa07032bbd1b8), X(0x19a4c116b8d2d0c8), X(0x1e376c085141ab53),
    X(0x2748774cdf8eeb99), X(0x34b0bcb5e19b48a8), X(0x391c0cb3c5c95a63), X(0x4ed8aa4ae3418acb), X(0x5b9cca4f7763e373),
    X(0x682e6ff3d6b2b8a3), X(0x748f82ee5defb2fc), X(0x78a5636f43172f60), X(0x84c87814a1f0ab72), X(0x8cc702081a6439ec),
    X(0x90befffa23631e28), X(0xa4506cebde82bde9), X(0xbef9a3f7b2c67915), X(0xc67178f2e372532b), X(0xca273eceea26619c),
    X(0xd186b8c721c0c207), X(0xeada7dd6cde0eb1e), X(0xf57d4f7fee6ed178), X(0x06f067aa72176fba), X(0x0a637dc5a2c898a6),
    X(0x113f9804bef90dae), X(0x1b710b35131c471b), X(0x28db77f523047d84), X(0x32caab7b40c72493), X(0x3c9ebe0a15c9bebc),
    X(0x431d67c49c100d4c), X(0x4cc5d4becb3e42b6), X(0x597f299cfc657e2a), X(0x5fcb6fab3ad6faec), X(0x6c44198c4a475817)
#undef X
};
#define R64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
static void cpu_compress(uint64_t st[8], const uint64_t blk[16]) {
    uint64_t w[80], a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 16; i++) w[i] = blk[i];
    for (int i = 16; i < 80; i++)
        w[i] = w[i - 16] + (R64(w[i - 15], 1) ^ R64(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 7] +
               (R64(w[i - 2], 19) ^ R64(w[i - 2], 61) ^ (w[i - 2] >> 6));
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + (R64(e, 14) ^ R64(e, 18) ^ R64(e, 41)) + ((e & f) ^ (~e & g)) + K512C[i] + w[i];
        uint64_t t2 = (R64(a, 28) ^ R64(a, 34) ^ R64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static void make_mkey(void) {
    static const uint64_t IV[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                                   0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    uint64_t kb[16], blk[16], st[16];
    key_block((const uint8_t *)"ed25519 seed", 12, kb);
    memcpy(st, IV, 64);
    for (int j = 0; j < 16; j++) blk[j] = kb[j] ^ 0x3636363636363636ULL;
    cpu_compress(st, blk);
    memcpy(st + 8, IV, 64);
    for (int j = 0; j < 16; j++) blk[j] = kb[j] ^ 0x5c5c5c5c5c5c5c5cULL;
    cpu_compress(st + 8, blk);
    gpu.mkey = const_buffer(st, 128);
}

// ---------------------------------------------------------------- hits and results

static mutex_t hit_lock, stat_lock;
static int verified, skipped;
static int dumped;
static FILE *dump_fp;
static double total_done; // phrases fully derived and checked

static void make_dir(const char *dir) {
#ifdef _WIN32
    CreateDirectoryA(dir, NULL);
#else
    mkdir(dir, 0700);
#endif
}

static void append_secret(const char *text) {
    char dir[4096];
    snprintf(dir, sizeof dir, "%s", opt.out);
    char *s = strrchr(dir, PATH_SEP);
    char *s2 = strrchr(dir, '/');
    if (s2 > s) s = s2;
    if (s) {
        *s = 0;
        make_dir(dir);
    }
#ifdef _WIN32
    int fd = _open(opt.out, _O_WRONLY | _O_CREAT | _O_APPEND | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) die("cannot open %s", opt.out);
    _write(fd, text, (unsigned)strlen(text));
    _close(fd);
#else
    int fd = open(opt.out, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) die("cannot open %s", opt.out);
    fchmod(fd, 0600);
    if (write(fd, text, strlen(text)) < 0) die("cannot write %s", opt.out);
    close(fd);
#endif
}

// Runs one verifier: sends {"words": phrase} on stdin, reads its JSON answer from a temp file.
// Fills uq / pub / as. Returns 0 if it could not run.
static int run_verifier(const char *cmd_prefix, const char *phrase, char *uq, char *pub, char *as) {
    char tmp[4200], cmd[9000];
    snprintf(tmp, sizeof tmp, "%s%cresults", root_dir, PATH_SEP);
    make_dir(tmp);
    snprintf(tmp, sizeof tmp, "%s%cresults%cverify-%d.tmp", root_dir, PATH_SEP, PATH_SEP, (int)(now_sec() * 1000) % 100000);
#ifdef _WIN32
    snprintf(cmd, sizeof cmd, "\"%s > \"%s\" 2>NUL\"", cmd_prefix, tmp); // cmd /c strips the outer quotes
#else
    snprintf(cmd, sizeof cmd, "%s > \"%s\" 2>/dev/null", cmd_prefix, tmp);
#endif
    FILE *p = popen(cmd, "w");
    if (!p) return 0;
    fprintf(p, "{\"words\":\"%s\"}\n", phrase);
    pclose(p);
    FILE *f = fopen(tmp, "rb");
    if (!f) return 0;
    char buf[2048] = {0};
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    remove(tmp);
    buf[n] = 0;
    const char *keys[3] = {"\"uq\":\"", "\"pub\":\"", "\"as\":\""};
    char *outs[3] = {uq, pub, as};
    for (int k = 0; k < 3; k++) {
        char *s = strstr(buf, keys[k]);
        outs[k][0] = 0;
        if (!s) return 0;
        s += strlen(keys[k]);
        char *e = strchr(s, '"');
        if (!e || e - s > 100) return 0;
        memcpy(outs[k], s, (size_t)(e - s));
        outs[k][e - s] = 0;
    }
    return 1;
}

static void handle_hit(const int *idx, int nw, const uint8_t priv_gpu[32]) {
    mutex_lock(&hit_lock);
    if (verified >= opt.count) { mutex_unlock(&hit_lock); return; }
    char phrase[256];
    size_t plen = phrase_bytes(idx, nw, phrase);
    // 1. independent CPU re-derivation of the key from the phrase
    uint8_t priv[32], pub[32], id[32];
    if (opt.mode == TON24) {
        uint8_t e[64], s[64];
        ton_entropy(phrase, plen, e);
        cpu_pbkdf2(e, 64, SALT_TON_DEFAULT, 16, TON_ITERS, s);
        memcpy(priv, s, 32);
    } else {
        uint8_t seed[64];
        cpu_pbkdf2((const uint8_t *)phrase, plen, SALT_MNEMONIC, 8, 2048, seed);
        cpu_slip10(seed, priv);
    }
    ed25519_public(priv, pub);
    w5_account_id(pub, id);
    char uq[49], eq[49], pubhex[65];
    friendly(id, 0, uq);
    friendly(id, 1, eq);
    hexs(pub, 32, pubhex);
    const char *shown = opt.bounceable ? eq : uq;
    int ok = memcmp(priv, priv_gpu, 32) == 0 && matches(shown);
    char checks[512];
    snprintf(checks, sizeof checks, "%s", ok ? "CPU re-derivation OK" : "CPU re-derivation MISMATCH");
    // 2. a phrase valid in both formats would be read differently by wallets: skip it
    int ambiguous = opt.mode == TON24 ? bip39_valid(idx, nw) : ton_valid(phrase, plen);
    if (ambiguous) {
        skipped++;
        printf("hit %s skipped: phrase is valid both as TON standard and as BIP39 (ambiguous in wallets)\n", shown);
        fflush(stdout);
        mutex_unlock(&hit_lock);
        return;
    }
    // 3. two independent libraries
    const char *want = opt.mode == TON24 ? "ton" : "bip39";
    if (opt.verify) {
        char c1[4400], c2[4400];
        snprintf(c1, sizeof c1, "node \"%s%cverify%cw5addr.mjs\"", root_dir, PATH_SEP, PATH_SEP);
#ifdef _WIN32
        snprintf(c2, sizeof c2, "\"%s%cverify-go%cw5addr.exe\"", root_dir, PATH_SEP, PATH_SEP);
#else
        snprintf(c2, sizeof c2, "\"%s%cverify-go%cw5addr\"", root_dir, PATH_SEP, PATH_SEP);
#endif
        const char *names[2] = {"@ton/ton", "tonutils-go"};
        const char *cmds[2] = {c1, c2};
        for (int k = 0; k < 2; k++) {
            char vuq[128], vpub[128], vas[128];
            int ran = run_verifier(cmds[k], phrase, vuq, vpub, vas);
            size_t l = strlen(checks);
            if (ran && !strcmp(vuq, uq) && !strcmp(vpub, pubhex) && !strcmp(vas, want)) {
                snprintf(checks + l, sizeof checks - l, ", %s OK", names[k]);
            } else {
                ok = 0;
                snprintf(checks + l, sizeof checks - l, ", %s %s", names[k], ran ? "MISMATCH" : "not runnable");
            }
        }
    } else {
        size_t l = strlen(checks);
        snprintf(checks + l, sizeof checks - l, ", libraries not run (--no-verify)");
    }
    char stamp[64], text[2048];
    time_t t = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    snprintf(text, sizeof text,
             "=== %s %s\nphrase (%d words, %s): %s\nwallet: W5 (v5r1), mainnet, workchain 0, subwallet 0\n"
             "public key: %s\naddress UQ (non-bounceable, shown by wallets): %s\naddress EQ (bounceable): %s\n"
             "independent checks: %s\n\n\n",
             ok ? "HIT" : "UNVERIFIED HIT, DO NOT USE", stamp, nw,
             opt.mode == TON24 ? "TON standard" : "BIP39, path m/44'/607'/0'", phrase, pubhex, uq, eq, checks);
    append_secret(text);
    crypto_wipe(phrase, sizeof phrase);
    crypto_wipe(text, sizeof text);
    if (ok) verified++;
    printf("%s %s  [%s]  phrase saved to %s\n", ok ? "HIT" : "UNVERIFIED HIT", shown, checks, opt.out);
    fflush(stdout);
    if (verified >= opt.count) {
        printf("done: %d verified hit(s)\n", verified);
        fflush(stdout);
        exit(0);
    }
    mutex_unlock(&hit_lock);
}

// Final CPU part for one derived private key: public key, W5 address, pattern check.
static void finish(const int *idx, int nw, const uint8_t priv[32]) {
    uint8_t pub[32], id[32];
    char addr[49];
    ed25519_public(priv, pub);
    w5_account_id(pub, id);
    friendly(id, opt.bounceable, addr);
    if (opt.dump) {
        mutex_lock(&stat_lock);
        if (dumped < opt.dump) {
            char phrase[256], uq[49], ph[65];
            phrase_bytes(idx, nw, phrase);
            friendly(id, 0, uq);
            hexs(pub, 32, ph);
            fprintf(dump_fp, "{\"words\":\"%s\",\"uq\":\"%s\",\"pub\":\"%s\",\"src\":\"opencl\"}\n", phrase, uq, ph);
            dumped++;
        }
        mutex_unlock(&stat_lock);
        return;
    }
    if (pattern_len && matches(addr)) handle_hit(idx, nw, priv);
}

// ---------------------------------------------------------------- BIP39 pipeline

typedef struct {
    uint32_t n;
    int entlen, nw;
    uint8_t *ent;   // n * entlen
    uint64_t *keys; // n * 16
    uint64_t *priv; // n * 4 (big-endian words)
    Job job;
} BipBatch;

static void bip_prep_fn(void *p, int tid, int nt) {
    BipBatch *b = (BipBatch *)p;
    int idx[24];
    char phrase[256];
    for (uint32_t i = (uint32_t)tid; i < b->n; i += (uint32_t)nt) {
        bip39_indices(b->ent + (size_t)i * b->entlen, b->entlen, idx);
        size_t l = phrase_bytes(idx, b->nw, phrase);
        key_block((const uint8_t *)phrase, l, b->keys + (size_t)i * 16);
    }
}

static void words_to_bytes(const uint64_t *w, int nwords, uint8_t *out) {
    for (int j = 0; j < nwords; j++)
        for (int k = 0; k < 8; k++) out[j * 8 + k] = (uint8_t)(w[j] >> (56 - 8 * k));
}

static void bip_post_fn(void *p, int tid, int nt) {
    BipBatch *b = (BipBatch *)p;
    int idx[24];
    uint8_t priv[32];
    for (uint32_t i = (uint32_t)tid; i < b->n; i += (uint32_t)nt) {
        bip39_indices(b->ent + (size_t)i * b->entlen, b->entlen, idx);
        words_to_bytes(b->priv + (size_t)i * 4, 4, priv);
        finish(idx, b->nw, priv);
    }
}

static BipBatch *bip_new(uint32_t n) {
    BipBatch *b = calloc(1, sizeof *b);
    b->n = n;
    b->entlen = opt.mode == BIP12 ? 16 : 32;
    b->nw = opt.mode == BIP12 ? 12 : 24;
    b->ent = malloc((size_t)n * b->entlen);
    b->keys = malloc((size_t)n * 128);
    b->priv = malloc((size_t)n * 32);
    if (!b->ent || !b->keys || !b->priv) die("out of memory");
    random_bytes(b->ent, (size_t)n * b->entlen);
    parallel(opt.threads, bip_prep_fn, b);
    job_submit(&b->job, b->keys, n, gpu.salt_mnemonic, 2048, 1, 0, b->priv);
    return b;
}

static void bip_free(BipBatch *b) {
    job_release(&b->job);
    crypto_wipe(b->ent, (size_t)b->n * b->entlen);
    free(b->ent); free(b->keys); free(b->priv); free(b);
}

// ---------------------------------------------------------------- TON pipeline

typedef struct { int idx[24]; uint8_t ent[64]; } TonCand;

typedef struct {
    uint32_t n;
    uint8_t *rnd;       // n * 33
    TonCand *cand;      // n
    uint64_t *keys;     // n * 16
    uint64_t *out;      // n * out_words
} TonBatch;

static void ton_prep_fn(void *p, int tid, int nt) {
    TonBatch *b = (TonBatch *)p;
    char phrase[256];
    for (uint32_t i = (uint32_t)tid; i < b->n; i += (uint32_t)nt) {
        TonCand *c = &b->cand[i];
        indices11(b->rnd + (size_t)i * 33, 24, c->idx);
        size_t l = phrase_bytes(c->idx, 24, phrase);
        ton_entropy(phrase, l, c->ent);
        key_block(c->ent, 64, b->keys + (size_t)i * 16);
    }
}

static TonCand *survivors;
static uint32_t n_surv, cap_surv;

static void ton_post_fn(void *p, int tid, int nt) {
    TonBatch *b = (TonBatch *)p;
    uint8_t priv[32];
    for (uint32_t i = (uint32_t)tid; i < b->n; i += (uint32_t)nt) {
        words_to_bytes(b->out + (size_t)i * 4, 4, priv);
        finish(b->cand[i].idx, 24, priv);
    }
}

// ---------------------------------------------------------------- self-test

static void self_test(void) {
    // 1. CPU primitives against published vectors
    uint8_t h[32], seed[64];
    sha256((const uint8_t *)"abc", 3, h);
    char hx[129];
    hexs(h, 32, hx);
    if (strcmp(hx, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) die("SELF-TEST FAILED: SHA-256");
    const char *abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    cpu_pbkdf2((const uint8_t *)abandon, strlen(abandon), SALT_MNEMONIC, 8, 2048, seed);
    hexs(seed, 64, hx);
    if (strcmp(hx, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"))
        die("SELF-TEST FAILED: CPU PBKDF2 vs BIP39 test vector");
    // 2. full derivation -> W5 address vs vectors produced by @ton/ton (throwaway phrases, never fund them)
    struct { int mode; const char *phrase, *want; } vec[3] = {
        {BIP12, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
         "UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT"},
        {BIP24, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "UQC020bHeiUqqyw8BB4EttblmRidKkT_hnINJ-8rZCP0L1Dw"},
        {TON24, "exercise lawn pole excite tape shy judge episode twice crazy pudding unfold unique fatal scrub parade "
                "cover pretty payment shrimp ahead humor shoe merit",
         "UQBDJxXesUgF7mvh4aoc0aa5kjKFE1Pquz1T-u9Y_e0VQk41"}};
    for (int v = 0; v < 3; v++) {
        uint8_t priv[32], pub[32], id[32], s[64];
        size_t l = strlen(vec[v].phrase);
        if (vec[v].mode == TON24) {
            uint8_t e[64];
            ton_entropy(vec[v].phrase, l, e);
            cpu_pbkdf2(e, 64, SALT_TON_DEFAULT, 16, TON_ITERS, s);
            memcpy(priv, s, 32);
        } else {
            cpu_pbkdf2((const uint8_t *)vec[v].phrase, l, SALT_MNEMONIC, 8, 2048, s);
            cpu_slip10(s, priv);
        }
        ed25519_public(priv, pub);
        w5_account_id(pub, id);
        char uq[49];
        friendly(id, 0, uq);
        if (strcmp(uq, vec[v].want)) die("SELF-TEST FAILED: %s W5 address %s != %s", MODE_NAME[vec[v].mode], uq, vec[v].want);
    }
    if (!ton_valid(vec[2].phrase, strlen(vec[2].phrase))) die("SELF-TEST FAILED: TON validity");
    // 3. GPU PBKDF2 + SLIP-10 == CPU, incl. >128-byte keys and chunked iterations
    enum { N = 40 };
    uint64_t keys[N * 16], out[N * 4], outt[N * 8];
    uint8_t pws[N][200];
    size_t lens[N];
    uint32_t saved = chunk_iters;
    chunk_iters = 700; // forces 3 chunks for 2048 iterations
    for (int i = 0; i < N; i++) {
        lens[i] = (size_t)(i % 3 == 0 ? 150 + i : 40 + i);
        random_bytes(pws[i], lens[i]);
        key_block(pws[i], lens[i], keys + i * 16);
    }
    Job j;
    job_submit(&j, keys, N, gpu.salt_mnemonic, 2048, 1, 0, out);
    job_wait(&j);
    job_release(&j);
    for (int i = 0; i < N; i++) {
        uint8_t ref[64], rp[32], got[32];
        cpu_pbkdf2(pws[i], lens[i], SALT_MNEMONIC, 8, 2048, ref);
        cpu_slip10(ref, rp);
        words_to_bytes(out + i * 4, 4, got);
        if (memcmp(rp, got, 32)) die("SELF-TEST FAILED: GPU PBKDF2+SLIP-10 != CPU (thread %d)", i);
    }
    job_submit(&j, keys, N, gpu.salt_ton_version, TON_BASIC_ITERS, 0, 8, outt);
    job_wait(&j);
    job_release(&j);
    for (int i = 0; i < N; i++) {
        uint8_t ref[64], got[64];
        cpu_pbkdf2(pws[i], lens[i], SALT_TON_VERSION, 16, TON_BASIC_ITERS, ref);
        words_to_bytes(outt + i * 8, 8, got);
        if (memcmp(ref, got, 64)) die("SELF-TEST FAILED: GPU PBKDF2 (TON salt) != CPU (thread %d)", i);
    }
    chunk_iters = saved;
    // 4. BIP39 checksum helper
    uint8_t ent[32];
    int idx[24];
    random_bytes(ent, 32);
    bip39_indices(ent, 16, idx);
    if (!bip39_valid(idx, 12)) die("SELF-TEST FAILED: BIP39 checksum (12)");
    bip39_indices(ent, 32, idx);
    if (!bip39_valid(idx, 24)) die("SELF-TEST FAILED: BIP39 checksum (24)");
}

// ---------------------------------------------------------------- main

int main(int argc, char **argv) {
#ifdef _WIN32
    setvbuf(stdout, NULL, _IONBF, 0); // the Windows CRT treats line buffering as full buffering
#else
    setvbuf(stdout, NULL, _IOLBF, 0);
#endif
    opt.mode = BIP12;
    opt.count = 1;
    opt.verify = 1;
    opt.threads = cpu_count();
    exe_dir(root_dir, sizeof root_dir);
    { // root = parent of the executable's directory
        char *s = strrchr(root_dir, PATH_SEP);
        if (s) *s = 0; else strcpy(root_dir, "..");
    }
    snprintf(opt.out, sizeof opt.out, "%s%cresults%cfound.txt", root_dir, PATH_SEP, PATH_SEP);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
#define NEXT() (i + 1 < argc ? argv[++i] : (die("missing value for %s", a), ""))
        if (!strcmp(a, "--suffix")) snprintf(opt.suffix, sizeof opt.suffix, "%s", NEXT());
        else if (!strcmp(a, "--mode")) {
            const char *m = NEXT();
            if (!strcmp(m, "bip39-12")) opt.mode = BIP12;
            else if (!strcmp(m, "bip39-24")) opt.mode = BIP24;
            else if (!strcmp(m, "ton-24")) opt.mode = TON24;
            else die("mode: bip39-12 | bip39-24 | ton-24");
        } else if (!strcmp(a, "--form")) {
            const char *f = NEXT();
            if (!strcmp(f, "uq")) opt.bounceable = 0;
            else if (!strcmp(f, "eq")) opt.bounceable = 1;
            else die("form: uq | eq");
        } else if (!strcmp(a, "--ignore-case")) opt.ignore_case = 1;
        else if (!strcmp(a, "--threads")) opt.threads = atoi(NEXT());
        else if (!strcmp(a, "--count")) opt.count = atoi(NEXT());
        else if (!strcmp(a, "--out")) snprintf(opt.out, sizeof opt.out, "%s", NEXT());
        else if (!strcmp(a, "--bench")) opt.bench = atof(NEXT());
        else if (!strcmp(a, "--dump")) { opt.dump = atoi(NEXT()); snprintf(opt.dump_file, sizeof opt.dump_file, "%s", NEXT()); }
        else if (!strcmp(a, "--no-verify")) opt.verify = 0;
        else if (!strcmp(a, "--device")) opt.device = atoi(NEXT());
        else if (!strcmp(a, "--list-devices")) opt.list_devices = 1;
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) usage(0);
        else usage(1);
    }
    if (opt.threads < 1) opt.threads = 1;
    if (opt.count < 1) opt.count = 1;
    if (!opt.bench && !opt.dump && !opt.list_devices && !opt.suffix[0]) die("--suffix is required (see --help)");
    parse_pattern(opt.suffix);
    mutex_init(&hit_lock);
    mutex_init(&stat_lock);

    gpu_init();
    make_mkey();
    double t0 = now_sec();
    self_test();
    printf("GPU %s; self-test OK (GPU PBKDF2 and SLIP-10 == CPU, W5 v5r1 addresses == @ton/ton) in %.1f s\n", gpu.name, now_sec() - t0);
    double expected = expected_tries();
    if (!opt.dump && !opt.bench) {
        printf("search: ending \"%s\"%s in %s form, mode %s, W5 v5r1 mainnet subwallet 0, %d CPU threads\n", opt.suffix,
               opt.ignore_case ? " (any case)" : "", opt.bounceable ? "EQ" : "UQ", MODE_NAME[opt.mode], opt.threads);
        printf("expected ~%.3g phrases; results -> %s (phrases are never printed)\n", expected, opt.out);
    }
    if (opt.dump) {
        dump_fp = fopen(opt.dump_file, "w");
        if (!dump_fp) die("cannot open %s", opt.dump_file);
    }

    double start = now_sec(), last_print = start, last_done = 0;
    uint32_t n = 16384, ton_stage2 = opt.dump ? (uint32_t)opt.dump : 16384;
    BipBatch *cur = NULL;
    for (;;) {
        double tb = now_sec();
        if (opt.mode != TON24) {
            // double buffering: the GPU works on the next batch while the CPU finishes the current one
            if (!cur) cur = bip_new(n);
            BipBatch *next = bip_new(n);
            job_wait(&cur->job);
            parallel(opt.threads, bip_post_fn, cur);
            tune_chunk(2048, cur->n, now_sec() - tb);
            mutex_lock(&stat_lock);
            total_done += cur->n;
            mutex_unlock(&stat_lock);
            bip_free(cur);
            cur = next;
        } else {
            // stage 1: basic-seed check (keeps 1/256), stage 2: key derivation for the survivors
            TonBatch b = {0};
            b.n = n;
            b.rnd = malloc((size_t)n * 33);
            b.cand = malloc((size_t)n * sizeof(TonCand));
            b.keys = malloc((size_t)n * 128);
            b.out = malloc((size_t)n * 8);
            if (!b.rnd || !b.cand || !b.keys || !b.out) die("out of memory");
            random_bytes(b.rnd, (size_t)n * 33);
            parallel(opt.threads, ton_prep_fn, &b);
            Job j;
            job_submit(&j, b.keys, n, gpu.salt_ton_version, TON_BASIC_ITERS, 0, 1, b.out);
            job_wait(&j);
            tune_chunk(TON_BASIC_ITERS, n, now_sec() - tb);
            job_release(&j);
            for (uint32_t i = 0; i < n; i++) {
                if ((b.out[i] >> 56) != 0) continue;
                if (n_surv == cap_surv) {
                    cap_surv = cap_surv ? cap_surv * 2 : 32768;
                    survivors = realloc(survivors, (size_t)cap_surv * sizeof(TonCand));
                    if (!survivors) die("out of memory");
                }
                survivors[n_surv++] = b.cand[i];
            }
            crypto_wipe(b.cand, (size_t)n * sizeof(TonCand));
            free(b.rnd); free(b.cand); free(b.keys); free(b.out);
            if (n_surv >= ton_stage2) {
                TonBatch s2 = {0};
                s2.n = ton_stage2;
                s2.cand = survivors;
                s2.keys = malloc((size_t)s2.n * 128);
                s2.out = malloc((size_t)s2.n * 32);
                if (!s2.keys || !s2.out) die("out of memory");
                for (uint32_t i = 0; i < s2.n; i++) key_block(survivors[i].ent, 64, s2.keys + (size_t)i * 16);
                job_submit(&j, s2.keys, s2.n, gpu.salt_ton_default, TON_ITERS, 0, 4, s2.out);
                job_wait(&j);
                job_release(&j);
                parallel(opt.threads, ton_post_fn, &s2);
                mutex_lock(&stat_lock);
                total_done += s2.n;
                mutex_unlock(&stat_lock);
                crypto_wipe(survivors, (size_t)s2.n * sizeof(TonCand));
                memmove(survivors, survivors + s2.n, (size_t)(n_surv - s2.n) * sizeof(TonCand));
                n_surv -= s2.n;
                free(s2.keys); free(s2.out);
            }
        }
        // adapt batch size: bigger batches for fast GPUs (up to 1M phrases), GPU time measured by profiling
        // batch size does not affect the kernel length (chunking does), only how often the CPU and GPU hand over
        double batch_est = iter_cost * 2048 * n; // conservative
        if (opt.mode != TON24 && iter_cost > 0 && batch_est < 1.5 && n < (1u << 20)) n *= 2;
        if (getenv("SEEDVANITY_DEBUG"))
            fprintf(stderr, "loop: n=%u loop %.3f s, profiled/iter %.2e s, est batch %.3f s, chunk %u\n", n,
                    now_sec() - tb, last_iter_time, batch_est, chunk_iters);

        double now = now_sec(), el = now - start;
        mutex_lock(&stat_lock);
        double done = total_done;
        int dmp = dumped;
        mutex_unlock(&stat_lock);
        if (opt.dump && dmp >= opt.dump) {
            fclose(dump_fp);
            printf("dumped %d phrases with their W5 addresses to %s\n", dmp, opt.dump_file);
            return 0;
        }
        if (opt.bench > 0 && el >= opt.bench) {
            printf("bench %s: %.0f phrases/s over %.0f s (batch %u); a 5-character ending (2^30) would take ~%.1f h on average\n",
                   MODE_NAME[opt.mode], done / el, el, n, pow(2, 30) / (done / el) / 3600);
            return 0;
        }
        if (!opt.bench && !opt.dump && now - last_print >= 30) {
            double rate = (done - last_done) / (now - last_print);
            char clk[16];
            clock_str(clk, sizeof clk);
            printf("[%s] %.2fM phrases, %.0f/s, %.1f%% of expected, chance found by now %.0f%%, avg remaining ~%.1f h\n",
                   clk, done / 1e6, rate, 100 * done / expected, 100 * (1 - exp(-done / expected)),
                   expected / (rate > 1 ? rate : 1) / 3600);
            last_print = now;
            last_done = done;
        }
    }
}
