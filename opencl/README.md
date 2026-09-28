# seedvanity for Linux and Windows (OpenCL)

The GPU computes PBKDF2-HMAC-SHA512 and, for BIP39, the SLIP-10 derivation along `m/44'/607'/0'`
(`kernel.cl`). The CPU computes Ed25519 public keys ([Monocypher](https://monocypher.org)), W5
addresses and the ending check on all threads. On a strong GPU the CPU is the limit; that is
expected.

> Verified for correctness on macOS's OpenCL and cross-compiled for Linux (x86_64, arm64) and Windows
> (x86_64). Not yet run on NVIDIA or AMD hardware or on Windows. The self-test on every start compares
> the GPU with the CPU and stops if they differ.

## Build on Linux (Ubuntu)

```sh
sudo apt install build-essential ocl-icd-opencl-dev clinfo
clinfo -l             # the GPU must be listed
make
```

GPU runtimes: NVIDIA's proprietary driver includes OpenCL; AMD: ROCm OpenCL; Intel:
`sudo apt install intel-opencl-icd`.

## Build on Windows

The GPU driver (NVIDIA, AMD or Intel) already contains OpenCL. Install [MSYS2](https://www.msys2.org/),
open the **MSYS2 UCRT64** shell and run:

```sh
pacman -S --needed make mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-opencl-icd mingw-w64-ucrt-x86_64-opencl-headers
cd /c/path/to/seedvanity/opencl
make
```

`seedvanity.exe` runs from the MSYS2 shell or a regular command prompt. Build the Go verifier as
`verify-go/w5addr.exe`.

## First run

```sh
./seedvanity --list-devices               # GPUs visible to OpenCL
./seedvanity --mode bip39-12 --bench 60   # batch size and kernel length tune themselves in 10-20 s
```

With several GPUs pick one with `--device N`.

## Search

```sh
./seedvanity --suffix '[a-z_]HELLO' --mode bip39-12
```

A progress line is printed every 30 s. On a hit the tool prints `HIT <address>` and exits
(`--count N` for more).

Long runs on Linux, detached, with a supervisor that restarts the search if it dies, and without
system sleep:

```sh
nohup setsid systemd-inhibit --what=sleep:idle ./supervise.sh '[a-z_]HELLO' bip39-12 \
  ../results/found.txt ../results/run.log >/dev/null 2>&1 &
tail -1 ../results/run.log                                   # progress
pkill -f supervise.sh; pkill -f "seedvanity --suffix"        # stop (supervisor first)
```

On Windows keep the window open and disable sleep in the power settings.

Options: `--mode bip39-12|bip39-24|ton-24`, `--form uq|eq`, `--ignore-case`, `--threads N` (CPU
threads, default: all), `--count N`, `--out FILE` (default `../results/found.txt`), `--bench SECONDS`,
`--device N`, `--list-devices`, `--no-verify`, `--dump N FILE` (writes N random phrases with their
addresses for external cross-checks).

## Troubleshooting

- `no OpenCL GPU found`: the GPU driver with OpenCL support is missing (`clinfo -l` on Linux).
- `OpenCL kernel build failed`: please report the full error text.
- `SELF-TEST FAILED`: the GPU or its driver computes wrong results. Do not search on that device.
- `SEEDVANITY_DEBUG=1` prints the batch size and kernel-length tuning of every loop.

## Technical notes

- Windows resets the GPU driver when a single kernel runs longer than ~2 s (TDR). PBKDF2 is therefore
  split into launches of `chunk` iterations with the state kept in GPU memory between them; each
  launch targets ~0.25 s. The cost per iteration is estimated conservatively, as the larger of the
  profiled kernel time and the wall time of the whole loop, and it only decays slowly, because some
  drivers (Apple's among them) report wrong profiling times or signal events late.
- Batches start at 16 384 phrases and grow up to 1M while a batch stays short; the GPU works on the
  next batch while the CPU finishes the previous one.
- Every hit is derived again on the CPU (Monocypher HMAC-SHA512 PBKDF2, SLIP-10, Ed25519) and must
  match the GPU result, then it is re-checked by both verifiers.
- Self-test on every start: SHA-256 and the BIP39 PBKDF2 test vector on the CPU, GPU against CPU
  for PBKDF2 and SLIP-10 (keys longer than 128 bytes, forced chunk boundaries), W5 addresses of fixed
  test phrases against values from @ton/ton, BIP39 checksums.
- `embedded.h` holds the kernel source and the BIP-0039 wordlist; regenerate it with `make embed`
  (python3) after editing `kernel.cl`, `sha512_consts.h` or `english.txt`.
- `third_party/monocypher/`: Monocypher, CC0 or 2-clause BSD (see `LICENCE.md`, `VERSION`).
