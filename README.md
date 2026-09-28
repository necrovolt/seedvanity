# seedvanity

**Vanity TON wallet addresses with a real seed phrase, GPU-accelerated.**

seedvanity searches for a seed phrase whose **W5 (v5r1)** wallet address ends with characters you
choose, for example `…HELLO`. The phrase is an ordinary one: import it into **Tonkeeper** or
**My Wallet**, select W5, and the wallet shows exactly that address.

## Versions

| Folder | Platforms | GPU | Notes |
|---|---|---|---|
| [`macos/`](macos/README.md) | macOS on Apple Silicon (M1 and newer) | Metal | fastest on a Mac; the CPU helps with the ARMv8.2 SHA-512 instructions; thermal guard; supervisor |
| [`opencl/`](opencl/README.md) | Linux, Windows | OpenCL 1.2: NVIDIA, AMD, Intel | Ed25519 runs on the CPU; supervisor on Linux |

> **Status of the OpenCL version.** It is verified for correctness on macOS's OpenCL (thousands of
> phrases cross-checked against two independent libraries) and compiles and links cleanly for Linux
> (x86_64, arm64) and Windows (x86_64), but it has not yet been run on NVIDIA or AMD hardware or on
> Windows. On every start it checks its GPU results against the CPU and refuses to search if they
> differ. Benchmarks and reports are welcome.

## Why not ton-org/vanity?

[ton-org/vanity](https://github.com/ton-org/vanity) is extremely fast, but it mines a salt for a
wrapper contract bound to an owner address. A wallet that imports your seed phrase computes the
standard address from the key and will not show that contract. seedvanity searches over seed phrases
instead, so the address is the one wallets derive on import. The price is that every candidate costs a
full key derivation, which is what the GPU is for.

## How it works

1. A random phrase from the operating system's CSPRNG: BIP39 (128 or 256 bits of entropy plus
   checksum) or a TON standard phrase (24 random words that pass the "basic seed" check).
2. PBKDF2-HMAC-SHA512 on the GPU: 2048 iterations for BIP39, 100 000 for the TON standard.
3. BIP39 only: SLIP-10 ed25519 derivation along `m/44'/607'/0'` (what Tonkeeper and My Wallet use).
4. Ed25519 public key.
5. W5 (v5r1) StateInit hash, user-friendly address, pattern match.
6. A hit is derived again independently and verified by two libraries before it is reported.

## Performance

Measured on an Apple M4 Pro (16-core GPU):

| | Phrases per second |
|---|---|
| `macos/`, GPU + 6 CPU threads | ~77 000 |
| `macos/`, GPU only (`--cpu 0`) | ~59 000 |
| `opencl/` on the same Mac (Apple's OpenCL) | ~52 000 |

The Metal kernel runs at ~97% of hashcat 7.1.2's PBKDF2-HMAC-SHA512 speed on the same GPU. On
discrete GPUs the OpenCL version is expected to be limited by the CPU, which computes Ed25519 keys at
roughly 35 000 to 50 000 per second per thread.

Average search time is 64^(number of characters) / speed. At 77 000 phrases/s:

| Ending | Average |
|---|---|
| 4 characters | ~4 min |
| 5 characters (`HELLO`) | ~4 h |
| `[a-z_]` + 5 characters | ~9 h |
| 6 characters | ~10 days |
| 7 characters | ~2 years |

The search is random: 50% of searches finish within 0.7x the average, 90% within 2.3x, 99% within
4.6x. Stopping and restarting loses nothing.

## Quick start

Requirements for the verifiers (all platforms): Node.js 18+ and Go 1.26+.

```sh
git clone <this repository> seedvanity && cd seedvanity
(cd verify && npm install)                   # @ton/ton verifier
go build -o verify-go/w5addr ./verify-go     # tonutils-go verifier (w5addr.exe on Windows)
```

**macOS** (Xcode Command Line Tools: `xcode-select --install`):

```sh
./macos/build.sh
cd macos && ./seedvanity --mode bip39-12 --bench 40
caffeinate -i ./seedvanity --suffix '[a-z_]HELLO' --mode bip39-12
```

**Linux** (Ubuntu: `sudo apt install build-essential ocl-icd-opencl-dev clinfo` plus the GPU driver
with OpenCL):

```sh
cd opencl && make
./seedvanity --list-devices
./seedvanity --mode bip39-12 --bench 60
./seedvanity --suffix '[a-z_]HELLO' --mode bip39-12
```

**Windows**: build in an MSYS2 UCRT64 shell, see [opencl/README.md](opencl/README.md).

## Usage

### Ending patterns

- Plain characters match as is, case-sensitive: `HELLO`.
- `[...]` matches one of the listed characters, ranges allowed: `[a-z_]HELLO` = a lowercase letter or
  `_`, then `HELLO`.
- `--ignore-case` ignores the case of letters.
- Addresses only contain `A-Z a-z 0-9 - _`. Quote patterns with `[...]` in the shell.
- The ending is matched in the non-bounceable form `UQ…` that wallets show for W5 (`--form eq` for
  `EQ…`). The two forms of one address end differently, because the last characters are a checksum.

### Modes (`--mode`)

| Mode | Phrase | Imports into | Speed |
|---|---|---|---|
| `bip39-12` | 12 words, BIP39, path m/44'/607'/0' | Tonkeeper, My Wallet | full |
| `bip39-24` | 24 words, BIP39, path m/44'/607'/0' | Tonkeeper, My Wallet | about the same |
| `ton-24` | 24 words, TON standard | every TON wallet, including Wallet in Telegram | ~100x slower |

Wallet: W5 (v5r1), mainnet (network id -239), workchain 0, subwallet 0.

Other options: `--count N` (stop after N hits, default 1), `--out FILE`, `--bench SECONDS`,
`--no-verify` (not recommended). Platform-specific options are described in each folder's README.

## Safety and verification

- Seed phrases are written **only** to the results file (`results/found.txt` or `--out`), never to
  the terminal. On macOS and Linux the file is created with mode 600.
- Every phrase gets fresh randomness from the operating system (`SecRandomCopyBytes` on macOS,
  `getrandom` on Linux, `BCryptGenRandom` on Windows). Everything runs locally, no network.
- Every hit is verified before it is reported: the key is derived again on the CPU (OpenCL version),
  then [`verify/w5addr.mjs`](verify/w5addr.mjs) (@ton/ton, @ton/crypto, bip39, ed25519-hd-key) and
  [`verify-go`](verify-go/main.go) (tonutils-go) re-derive the address with the wallets' own import
  logic. A hit that does not match exactly is written as `UNVERIFIED HIT, DO NOT USE`.
- Phrases that wallets could read two ways (valid both as BIP39 and as a TON standard phrase) are
  skipped: Tonkeeper tries the TON standard first, My Wallet tries BIP39 first.
- A self-test runs on every start: GPU against CPU PBKDF2 (and SLIP-10), W5 addresses of fixed test
  phrases against values from @ton/ton, BIP39 test vectors. The test phrases in the source code are
  public test vectors or throwaway phrases created for the tests; never send funds to them.
- Before sending real money: import the phrase, select W5, compare the address and make a small test
  transfer out and back. Then write the phrase down and delete the results file.

## Project layout

- `macos/`: Swift + Metal version. Technical notes: [macos/README.md](macos/README.md).
- `opencl/`: C + OpenCL version. Build and technical notes: [opencl/README.md](opencl/README.md).
- `verify/`: verifier based on @ton/ton (JavaScript).
- `verify-go/`, `go.mod`, `go.sum`: verifier based on tonutils-go (Go).
- `results/`: created at run time for hits and logs; ignored by git.

## Disclaimer

Provided as is, without warranty of any kind. You are responsible for checking every address before
using it.

## License

MIT, see [LICENSE](LICENSE). Third-party notices: [NOTICE](NOTICE).
