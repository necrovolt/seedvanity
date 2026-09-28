# seedvanity for macOS (Metal)

The GPU (Metal) does the heavy part, turning a phrase into a key (PBKDF2-HMAC-SHA512). The CPU does
the rest (SLIP-10, Ed25519, the W5 address, the ending check) and, with worker threads, also derives
phrases itself using the ARMv8.2 SHA-512 instructions (`cpu_pbkdf2.c`).

Requires macOS on Apple Silicon (M1 and newer) and the Xcode Command Line Tools
(`xcode-select --install`). The Metal shader is compiled at run time, the separate Metal toolchain
is not needed.

## Build and run

```sh
./build.sh                                                   # builds ./seedvanity
./seedvanity --mode bip39-12 --bench 40                       # speed only
caffeinate -i ./seedvanity --suffix HELLO --mode bip39-12     # caffeinate keeps the Mac awake
caffeinate -i ./seedvanity --suffix '[a-z_]HELLO' --mode bip39-12
```

Options: `--form uq|eq`, `--ignore-case`, `--count N` (stop after N hits), `--cpu N` (CPU worker
threads, default: performance cores minus 2; `--cpu 0` = GPU only, gentler for daytime use),
`--out FILE` (default `../results/found.txt`), `--bench SECONDS`.

## Long runs

Start under the supervisor, detached from the terminal session. If the search dies, the supervisor
restarts it (up to 5 times, silent notification); a hit shows a notification with sound.

```sh
python3 detach.py ./supervise.sh '[a-z_]HELLO' bip39-12 ../results/found.txt ../results/run.log
tail -1 ../results/run.log                                    # progress
pkill -f supervise.sh; pkill -f "seedvanity --suffix"         # stop (supervisor first)
```

## Thermal guard

The tool reads `ProcessInfo.thermalState`, the state macOS itself throttles on. At `serious` the CPU
workers pause, at `critical` the GPU pauses too; both resume when the Mac cools down. Every progress
line shows the state. `SEEDVANITY_THERMAL=serious|critical` simulates it for testing.

## Technical notes

- GPU alone: ~59 000 phrases/s on an M4 Pro = 122 M HMAC-SHA512/s. hashcat 7.1.2 on the same GPU
  does PBKDF2-HMAC-SHA512 at 126 M/s and raw SHA-512 at 285 M/s, so the kernel is at ~97% of
  hashcat. Tried and not kept: rotations on 32-bit halves (-4%), the Maj reuse trick (+0.4%, noise).
- CPU part: `cpu_pbkdf2.c` follows the round structure of Go's arm64 SHA-512 implementation (see
  NOTICE) and runs two derivations interleaved per thread: ~4 200 phrases/s per performance core,
  2.3x CommonCrypto. Worker threads must use QoS `.default`: with `.utility` macOS schedules them on
  the efficiency cores and they add half as much.
- Measured with the GPU running: 4 threads +9-10k/s, 6 threads +19k/s, 8 threads +21k/s.
- The main loop drains an autorelease pool every batch. Without it every batch leaked its Metal
  buffers (~1.3 GB per minute) and macOS killed the process after about an hour; memory now stays at
  ~125 MB.
- Every start runs a self-test: GPU and CPU PBKDF2 against CommonCrypto (including keys longer than
  128 bytes), W5 addresses of fixed test phrases against values from @ton/ton, BIP39 checksums.
- `bench.swift` is a standalone benchmark of the PBKDF2 kernel (`swiftc -O bench.swift -o bench`).
- `--dump N FILE` writes N random phrases with their addresses for external cross-checks with
  `../verify/w5addr.mjs` and `../verify-go`.

Files: `main.swift` (the tool), `pbkdf2.metal` (kernel), `sha512_consts.h` (SHA-512 constants
computed from primes), `cpu_pbkdf2.c/.h`, `english.txt` (BIP-0039 wordlist, SHA-256 checked by
`build.sh`), `supervise.sh`, `detach.py`, `bench.swift`.
