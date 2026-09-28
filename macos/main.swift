// seedvanity: finds a seed phrase whose TON W5 (v5r1) wallet address ends with a given suffix.
// The heavy part (PBKDF2-HMAC-SHA512) runs on the Mac GPU (Metal), the rest on the CPU.
//
// Wallet: W5 = v5r1, mainnet (network id -239), workchain 0, subwallet 0: the address Tonkeeper shows.
// Modes:
//   bip39-12 / bip39-24  BIP39 phrase, key via SLIP-10 m/44'/607'/0' (Tonkeeper, MyTonWallet import it)
//   ton-24               TON standard phrase (every TON wallet), ~100x more expensive per phrase
// Seed phrases are written only to the results file (chmod 600), never to stdout.
// Every hit is re-derived by two independent libraries (@ton/ton, tonutils-go) before it is reported.
//
// Build: ./build.sh   Run: ./seedvanity --suffix HELLO --mode bip39-12
import CommonCrypto
import CryptoKit
import Foundation
import Metal
import Security

setvbuf(stdout, nil, _IOLBF, 0)

func die(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}
func orDie<T>(_ v: T?, _ msg: String) -> T {
    guard let v else { die(msg) }
    return v
}

// MARK: - options

enum Mode: String { case bip12 = "bip39-12", bip24 = "bip39-24", ton24 = "ton-24" }

// Default CPU workers: performance cores minus 2 (they keep the GPU fed and the Mac responsive).
// Measured on a chip with 8 performance cores: 6 threads add ~+19 000/s with no loss on the GPU side.
func defaultCpuWorkers() -> Int {
    var p: Int32 = 0
    var n = MemoryLayout<Int32>.size
    guard sysctlbyname("hw.perflevel0.physicalcpu", &p, &n, nil, 0) == 0, p > 0 else { return 2 }
    return max(0, Int(p) - 2)
}

struct Options {
    var suffix = ""
    var mode = Mode.bip12
    var bounceable = false
    var ignoreCase = false
    var cpuWorkers = defaultCpuWorkers()
    var count = 1
    var out = ""
    var bench = 0.0
    var dump = 0
    var dumpFile = ""
    var verify = true
}

let rootDir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().deletingLastPathComponent()

var opt = Options()
opt.out = rootDir.appendingPathComponent("results/found.txt").path
do {
    var a = Array(CommandLine.arguments.dropFirst())
    func next(_ name: String) -> String {
        if a.isEmpty { die("missing value for \(name)") }
        return a.removeFirst()
    }
    while !a.isEmpty {
        let k = a.removeFirst()
        switch k {
        case "--suffix": opt.suffix = next(k)
        case "--mode": opt.mode = orDie(Mode(rawValue: next(k)), "mode: bip39-12 | bip39-24 | ton-24")
        case "--form":
            switch next(k) {
            case "uq": opt.bounceable = false
            case "eq": opt.bounceable = true
            default: die("form: uq | eq")
            }
        case "--ignore-case": opt.ignoreCase = true
        case "--cpu": opt.cpuWorkers = orDie(Int(next(k)), "--cpu N")
        case "--count": opt.count = orDie(Int(next(k)), "--count N")
        case "--out": opt.out = next(k)
        case "--bench": opt.bench = orDie(Double(next(k)), "--bench SECONDS")
        case "--dump": opt.dump = orDie(Int(next(k)), "--dump N FILE"); opt.dumpFile = next(k)
        case "--no-verify": opt.verify = false
        default:
            print("""
            usage: seedvanity --suffix '[a-z_]HELLO' [--mode bip39-12|bip39-24|ton-24] [--form uq|eq]
                             [--ignore-case] [--cpu N] [--count N] [--out FILE] [--bench SEC]
              --suffix       ending; [..] = one of the listed characters, ranges allowed
              --form uq      non-bounceable form UQ... (what wallets show for W5), default
              --cpu N        CPU worker threads next to the GPU (default: performance cores - 2, 0 = GPU only);
                             they pause while macOS reports a serious thermal state
              --count N      stop after N verified hits (default 1)
            """)
            exit(k == "--help" || k == "-h" ? 0 : 1)
        }
    }
    let b64 = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if opt.bench == 0 && opt.dump == 0 && opt.suffix.isEmpty { die("--suffix is required (see --help)") }
    _ = b64
}

// Suffix pattern: plain characters and [...] classes with ranges, e.g. "[a-z_]HELLO".
// pattern[k][c] == true if byte c is allowed at position k (counted from the start of the suffix).
let pattern: [[Bool]] = {
    let b64 = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
    let s = Array(opt.suffix.utf8)
    var out = [[Bool]]()
    var i = 0
    func allow(_ set: inout [Bool], _ c: UInt8) {
        guard b64.contains(c) else { die("pattern may contain only A-Z a-z 0-9 - _ and [...] classes") }
        set[Int(c)] = true
        if opt.ignoreCase, (65...90).contains(c) || (97...122).contains(c) { set[Int(c ^ 0x20)] = true }
    }
    while i < s.count {
        var set = [Bool](repeating: false, count: 256)
        if s[i] == UInt8(ascii: "[") {
            guard let close = s[i...].firstIndex(of: UInt8(ascii: "]")), close > i + 1 else { die("unclosed [ in pattern") }
            var j = i + 1
            while j < close {
                if j + 2 < close, s[j + 1] == UInt8(ascii: "-") {
                    guard s[j] <= s[j + 2] else { die("bad range in pattern") }
                    for c in s[j]...s[j + 2] where b64.contains(c) { allow(&set, c) }
                    j += 3
                } else {
                    allow(&set, s[j])
                    j += 1
                }
            }
            i = close + 1
        } else {
            allow(&set, s[i])
            i += 1
        }
        out.append(set)
    }
    if out.count > 10 { die("pattern longer than 10 characters is hopeless") }
    return out
}()

// MARK: - crypto helpers

let words: [String] = wordlistRaw.split(separator: "\n").map(String.init)
if words.count != 2048 { die("bad wordlist") }
let wordBytes: [[UInt8]] = words.map { Array($0.utf8) }

func sha256(_ b: [UInt8]) -> [UInt8] {
    var d = [UInt8](repeating: 0, count: 32)
    CC_SHA256(b, CC_LONG(b.count), &d)
    return d
}
func sha512(_ b: [UInt8]) -> [UInt8] {
    var d = [UInt8](repeating: 0, count: 64)
    CC_SHA512(b, CC_LONG(b.count), &d)
    return d
}
func hmac512(key: [UInt8], data: [UInt8]) -> [UInt8] {
    var d = [UInt8](repeating: 0, count: 64)
    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512), key, key.count, data, data.count, &d)
    return d
}
func cpuPBKDF2(_ pw: [UInt8], _ salt: [UInt8], _ iters: UInt32) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 64)
    let p = pw.map { CChar(bitPattern: $0) }
    let rc = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), p, p.count, salt, salt.count,
                                  CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), iters, &out, 64)
    if rc != 0 { die("CCKeyDerivationPBKDF failed") }
    return out
}
func randomBytes(_ n: Int) -> [UInt8] {
    var b = [UInt8](repeating: 0, count: n)
    if SecRandomCopyBytes(kSecRandomDefault, n, &b) != errSecSuccess { die("SecRandomCopyBytes failed") }
    return b
}
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> [UInt8] {
    let c = Array(s.utf8)
    return stride(from: 0, to: c.count, by: 2).map { UInt8(String(bytes: c[$0..<$0 + 2], encoding: .ascii)!, radix: 16)! }
}

let saltMnemonic = Array("mnemonic".utf8)
let saltTonVersion = Array("TON seed version".utf8)
let saltTonDefault = Array("TON default seed".utf8)
let tonBasicIters = 390 // max(1, 100000 / 256)
let tonIters = 100_000

// 11-bit word indices from a bit string (BIP39 entropy||checksum, or raw random bits for TON)
func indices11(_ b: [UInt8], count: Int) -> [Int] {
    var out = [Int]()
    out.reserveCapacity(count)
    var acc: UInt32 = 0, nbits = 0, pos = 0
    for _ in 0..<count {
        while nbits < 11 { acc = (acc << 8) | UInt32(b[pos]); pos += 1; nbits += 8 }
        out.append(Int((acc >> UInt32(nbits - 11)) & 0x7FF))
        nbits -= 11
        acc &= (1 << UInt32(nbits)) - 1
    }
    return out
}
func bip39Indices(entropy: [UInt8]) -> [Int] {
    indices11(entropy + [sha256(entropy)[0]], count: entropy.count * 3 / 4)
}
// BIP39 checksum validity of an arbitrary word sequence (12/15/18/21/24 words)
func isBip39Valid(_ idx: [Int]) -> Bool {
    guard [12, 15, 18, 21, 24].contains(idx.count) else { return false }
    var bits = [Bool]()
    for i in idx { for k in (0..<11).reversed() { bits.append((i >> k) & 1 == 1) } }
    let entBits = idx.count * 11 * 32 / 33, csBits = idx.count * 11 - entBits
    var ent = [UInt8](repeating: 0, count: entBits / 8)
    for k in 0..<entBits where bits[k] { ent[k / 8] |= 0x80 >> UInt8(k % 8) }
    let h = sha256(ent)[0]
    for k in 0..<csBits where bits[entBits + k] != ((h >> UInt8(7 - k)) & 1 == 1) { return false }
    return true
}
func phraseBytes(_ idx: [Int]) -> [UInt8] {
    var p = [UInt8]()
    p.reserveCapacity(idx.count * 9)
    for (k, i) in idx.enumerated() {
        if k > 0 { p.append(0x20) }
        p += wordBytes[i]
    }
    return p
}
func phraseString(_ idx: [Int]) -> String { idx.map { words[$0] }.joined(separator: " ") }
func tonEntropy(_ phrase: [UInt8]) -> [UInt8] { hmac512(key: phrase, data: []) }
// TON standard validity (what @ton/crypto mnemonicValidate checks, without password)
func isTonValid(_ phrase: [UInt8]) -> Bool { cpuPBKDF2(tonEntropy(phrase), saltTonVersion, UInt32(tonBasicIters))[0] == 0 }

// SLIP-0010 ed25519, path m/44'/607'/0'
func slip10(_ seed: [UInt8]) -> [UInt8] {
    var I = hmac512(key: Array("ed25519 seed".utf8), data: seed)
    for idx: UInt32 in [44, 607, 0] {
        let i = idx | 0x8000_0000
        let data: [UInt8] = [0] + I[0..<32] + [UInt8(i >> 24), UInt8((i >> 16) & 0xFF), UInt8((i >> 8) & 0xFF), UInt8(i & 0xFF)]
        I = hmac512(key: Array(I[32..<64]), data: data)
    }
    return Array(I[0..<32])
}
func ed25519Public(_ seed32: [UInt8]) -> [UInt8] {
    let k = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed32)
    return [UInt8](k.publicKey.rawRepresentation)
}

// MARK: - W5 (v5r1) address

// Code cell of wallet v5r1 (as in @ton/ton WalletContractV5R1, tonutils-go ConfigV5R1Final): hash + depth.
let w5CodeHash = unhex("20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f")
let w5CodeDepth: [UInt8] = [0x00, 0x06]
// wallet_id = network_global_id (-239) XOR context{client=1, workchain=0, version=v5r1(0), subwallet=0}
let w5WalletId: UInt32 = UInt32(bitPattern: -239) ^ 0x8000_0000 // 2147483409
let crcTable: [UInt16] = (0..<256).map { i in
    var c = UInt16(i) << 8
    for _ in 0..<8 { c = (c & 0x8000) != 0 ? (c << 1) ^ 0x1021 : c << 1 }
    return c
}
let b64chars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

// State-init hash of W5 for a public key = the account id (address hash)
func w5AccountId(_ pub: [UInt8]) -> [UInt8] {
    // data cell, 322 bits: is_signature_allowed=1 | seqno:32=0 | wallet_id:32 | public_key:256 | extensions=empty(0)
    var data = [UInt8](repeating: 0, count: 2 + 41)
    data[0] = 0x00 // refs=0, level=0
    data[1] = 81 // floor(322/8) + ceil(322/8)
    data[2] = 0x80
    let y: [UInt8] = [UInt8(w5WalletId >> 24), UInt8((w5WalletId >> 16) & 0xFF), UInt8((w5WalletId >> 8) & 0xFF), UInt8(w5WalletId & 0xFF)] + pub
    // bits 32.. = one zero bit (seqno LSB) + y, i.e. y shifted right by 1
    var prev: UInt8 = 0
    for k in 0..<36 { data[2 + 4 + k] = (prev << 7) | (y[k] >> 1); prev = y[k] }
    data[2 + 40] = (prev << 7) | 0x20 // last pubkey bit, extensions bit 0, completion tag
    let dataHash = sha256(data)
    // StateInit: split_depth 0, special 0, code 1, data 1, library 0 -> "00110" + tag = 0x34, 2 refs
    return sha256([0x02, 0x01, 0x34] + w5CodeDepth + [0x00, 0x00] + w5CodeHash + dataHash)
}
func friendly(_ accountId: [UInt8], bounceable: Bool) -> [UInt8] {
    var b: [UInt8] = [bounceable ? 0x11 : 0x51, 0x00] + accountId
    var crc: UInt16 = 0
    for x in b { crc = (crc << 8) ^ crcTable[Int(UInt8(crc >> 8) ^ x)] }
    b += [UInt8(crc >> 8), UInt8(crc & 0xFF)]
    var out = [UInt8]()
    out.reserveCapacity(48)
    for i in stride(from: 0, to: 36, by: 3) {
        let v = UInt32(b[i]) << 16 | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2])
        out += [b64chars[Int(v >> 18)], b64chars[Int((v >> 12) & 63)], b64chars[Int((v >> 6) & 63)], b64chars[Int(v & 63)]]
    }
    return out
}
@inline(__always) func matches(_ addr: [UInt8]) -> Bool {
    let off = addr.count - pattern.count
    for k in (0..<pattern.count).reversed() where !pattern[k][Int(addr[off + k])] { return false }
    return true
}

// MARK: - GPU

func keyBlock(_ pw: [UInt8], into dst: UnsafeMutablePointer<UInt64>) {
    let k = pw.count > 128 ? sha512(pw) : pw
    for j in 0..<16 {
        var w: UInt64 = 0
        for b in 0..<8 { let i = j * 8 + b; w = (w << 8) | UInt64(i < k.count ? k[i] : 0) }
        dst[j] = w
    }
}
func saltBlock(_ salt: [UInt8]) -> [UInt64] {
    var b = salt + [0, 0, 0, 1, 0x80]
    b += [UInt8](repeating: 0, count: 120 - b.count)
    let bits = UInt64(128 + salt.count + 4) * 8
    b += (0..<8).map { UInt8(truncatingIfNeeded: bits >> (56 - 8 * $0)) }
    return stride(from: 0, to: 128, by: 8).map { i in b[i..<i + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } }
}

struct Job {
    let state: MTLBuffer
    let cbs: [MTLCommandBuffer]
    let n: Int
    func wait() {
        cbs.last!.waitUntilCompleted()
        for cb in cbs where cb.status != .completed { die("GPU command buffer failed: \(String(describing: cb.error))") }
    }
    // PBKDF2 output (64 bytes) of thread i
    func output(_ i: Int) -> [UInt8] {
        let p = state.contents().bindMemory(to: UInt64.self, capacity: n * 32)
        var o = [UInt8](repeating: 0, count: 64)
        for j in 0..<8 { let w = p[i * 32 + 24 + j]; for b in 0..<8 { o[j * 8 + b] = UInt8(truncatingIfNeeded: w >> (56 - 8 * UInt64(b))) } }
        return o
    }
    func firstByte(_ i: Int) -> UInt8 {
        UInt8(state.contents().bindMemory(to: UInt64.self, capacity: n * 32)[i * 32 + 24] >> 56)
    }
}

final class GPU {
    let dev: MTLDevice
    let queue: MTLCommandQueue
    let initP: MTLComputePipelineState
    let iterP: MTLComputePipelineState
    init() {
        guard let d = MTLCreateSystemDefaultDevice() else { die("no Metal GPU") }
        dev = d
        let lib: MTLLibrary
        do { lib = try d.makeLibrary(source: kernelSource, options: nil) } catch { die("Metal compile: \(error)") }
        initP = try! d.makeComputePipelineState(function: lib.makeFunction(name: "pbkdf2_init")!)
        iterP = try! d.makeComputePipelineState(function: lib.makeFunction(name: "pbkdf2_iter")!)
        queue = d.makeCommandQueue()!
    }
    func keysBuffer(_ n: Int) -> MTLBuffer { dev.makeBuffer(length: n * 128, options: .storageModeShared)! }
    // Commits the whole derivation as a chain of short command buffers (~0.5 s each).
    func pbkdf2(keys: MTLBuffer, n: Int, salt: [UInt64], iters: Int) -> Job {
        let state = dev.makeBuffer(length: n * 256, options: .storageModeShared)!
        let chunk = max(1, min(2100, 70_000_000 / n)) // keeps each command buffer ~0.5 s
        var cbs = [MTLCommandBuffer]()
        var remaining = iters - 1, first = true
        var nn = UInt32(n)
        let tg = MTLSize(width: 1024, height: 1, depth: 1), grid = MTLSize(width: n, height: 1, depth: 1)
        repeat {
            let cb = queue.makeCommandBuffer()!
            let enc = cb.makeComputeCommandEncoder()!
            if first {
                enc.setComputePipelineState(initP)
                enc.setBuffer(keys, offset: 0, index: 0)
                enc.setBytes(salt, length: 128, index: 1)
                enc.setBuffer(state, offset: 0, index: 2)
                enc.setBytes(&nn, length: 4, index: 3)
                enc.dispatchThreads(grid, threadsPerThreadgroup: MTLSize(width: min(1024, initP.maxTotalThreadsPerThreadgroup), height: 1, depth: 1))
                first = false
            }
            var k = UInt32(min(remaining, chunk))
            if k > 0 {
                enc.setComputePipelineState(iterP)
                enc.setBuffer(state, offset: 0, index: 0)
                enc.setBytes(&k, length: 4, index: 1)
                enc.setBytes(&nn, length: 4, index: 2)
                enc.dispatchThreads(grid, threadsPerThreadgroup: MTLSize(width: min(tg.width, iterP.maxTotalThreadsPerThreadgroup), height: 1, depth: 1))
            }
            remaining -= Int(k)
            enc.endEncoding()
            cb.commit()
            cbs.append(cb)
        } while remaining > 0
        return Job(state: state, cbs: cbs, n: n)
    }
}

// MARK: - shared state

final class Shared: @unchecked Sendable {
    let lock = NSLock()
    var gpuDone = 0, cpuDone = 0, stage1 = 0
    var verified = 0, skipped = 0
    var dumped = 0
    var dumpLines = [String]()
    func add(gpu: Int = 0, cpu: Int = 0, s1: Int = 0) { lock.lock(); gpuDone += gpu; cpuDone += cpu; stage1 += s1; lock.unlock() }
}
let shared = Shared()
let hitLock = NSLock() // serialises hit handling (verification + file writes)

// MARK: - hits

struct VerifyResult: Decodable { let uq: String?; let eq: String?; let pub: String?; let `as`: String?; let error: String? }

func runVerifier(_ exe: String, _ args: [String], cwd: URL, input: String) -> VerifyResult? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: exe)
    p.arguments = args
    p.currentDirectoryURL = cwd
    let inPipe = Pipe(), outPipe = Pipe()
    p.standardInput = inPipe
    p.standardOutput = outPipe
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return nil }
    inPipe.fileHandleForWriting.write(input.data(using: .utf8)!)
    try? inPipe.fileHandleForWriting.close()
    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return try? JSONDecoder().decode(VerifyResult.self, from: data)
}

func appendSecret(_ text: String) {
    try? FileManager.default.createDirectory(atPath: (opt.out as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    let fd = open(opt.out, O_WRONLY | O_CREAT | O_APPEND, 0o600)
    if fd < 0 { die("cannot open \(opt.out)") }
    fchmod(fd, 0o600)
    let d = Array(text.utf8)
    _ = d.withUnsafeBufferPointer { write(fd, $0.baseAddress, d.count) }
    close(fd)
}

// Returns true if the hit was accepted.
func handleHit(_ idx: [Int], pub: [UInt8], accountId: [UInt8]) {
    hitLock.lock()
    defer { hitLock.unlock() }
    if shared.verified >= opt.count { return }
    let phrase = phraseBytes(idx)
    let uq = String(decoding: friendly(accountId, bounceable: false), as: UTF8.self)
    let eq = String(decoding: friendly(accountId, bounceable: true), as: UTF8.self)
    let shown = opt.bounceable ? eq : uq
    // A phrase valid in both formats would be read differently by wallets: skip it.
    let ambiguous = opt.mode == .ton24 ? isBip39Valid(idx) : isTonValid(phrase)
    if ambiguous {
        shared.skipped += 1
        print("hit \(shown) skipped: phrase is valid both as TON standard and as BIP39 (ambiguous in wallets)")
        return
    }
    let expectAs = opt.mode == .ton24 ? "ton" : "bip39"
    var checks = [String]()
    var ok = true
    if opt.verify {
        let line = "{\"words\":\"\(phraseString(idx))\"}\n"
        let v1 = runVerifier("/usr/bin/env", ["node", "w5addr.mjs"], cwd: rootDir.appendingPathComponent("verify"), input: line)
        let v2 = runVerifier(rootDir.appendingPathComponent("verify-go/w5addr").path, [], cwd: rootDir, input: line)
        for (name, v) in [("@ton/ton", v1), ("tonutils-go", v2)] {
            if let v, v.error == nil, v.uq == uq, v.eq == eq, v.pub == hex(pub), v.as == expectAs {
                checks.append("\(name) OK")
            } else {
                ok = false
                checks.append("\(name) MISMATCH (\(v.map { "\($0.uq ?? $0.error ?? "?")" } ?? "not runnable"))")
            }
        }
    } else {
        checks.append("not verified (--no-verify)")
    }
    let stamp = ISO8601DateFormatter().string(from: Date())
    appendSecret("""
    === \(ok ? "HIT" : "UNVERIFIED HIT, DO NOT USE") \(stamp)
    phrase (\(idx.count) words, \(opt.mode == .ton24 ? "TON standard" : "BIP39, path m/44'/607'/0'")): \(phraseString(idx))
    wallet: W5 (v5r1), mainnet, workchain 0, subwallet 0
    public key: \(hex(pub))
    address UQ (non-bounceable, shown by wallets): \(uq)
    address EQ (bounceable): \(eq)
    independent checks: \(checks.joined(separator: ", "))


    """)
    if ok { shared.verified += 1 }
    print("\(ok ? "HIT" : "UNVERIFIED HIT") \(shown)  [\(checks.joined(separator: ", "))]  phrase saved to \(opt.out)")
    if shared.verified >= opt.count {
        print("done: \(shared.verified) verified hit(s)")
        exit(0)
    }
}

// Final CPU part for one derived private key: W5 address + suffix check (+ dump for tests).
@inline(__always) func finish(_ idx: () -> [Int], priv: [UInt8], src: String = "gpu") {
    let pub = ed25519Public(priv)
    let id = w5AccountId(pub)
    let addr = friendly(id, bounceable: opt.bounceable)
    if opt.dump > 0 {
        shared.lock.lock()
        if shared.dumped < opt.dump {
            shared.dumped += 1
            shared.dumpLines.append("{\"words\":\"\(phraseString(idx()))\",\"uq\":\"\(String(decoding: friendly(id, bounceable: false), as: UTF8.self))\",\"pub\":\"\(hex(pub))\",\"src\":\"\(src)\"}")
        }
        shared.lock.unlock()
        return
    }
    if !pattern.isEmpty && matches(addr) { handleHit(idx(), pub: pub, accountId: id) }
}

// MARK: - self-test (runs on every start, ~1 s)

func selfTest(_ gpu: GPU) {
    // 1. GPU PBKDF2 == CommonCrypto, incl. >128-byte keys and chunk boundaries
    let n = 48
    let pws: [[UInt8]] = (0..<n).map { i in randomBytes(i % 3 == 0 ? 150 + i : 60 + i) }
    for (salt, iters) in [(saltMnemonic, 2048), (saltTonVersion, tonBasicIters)] {
        let kb = gpu.keysBuffer(n)
        let kp = kb.contents().bindMemory(to: UInt64.self, capacity: n * 16)
        for i in 0..<n { keyBlock(pws[i], into: kp + i * 16) }
        let job = gpu.pbkdf2(keys: kb, n: n, salt: saltBlock(salt), iters: iters)
        job.wait()
        for i in 0..<n where job.output(i) != cpuPBKDF2(pws[i], salt, UInt32(iters)) { die("SELF-TEST FAILED: GPU PBKDF2 mismatch") }
    }
    // 2. full derivation -> W5 address vs vectors produced by @ton/ton (throwaway phrases, never fund them)
    let vectors: [(Mode, String, String)] = [
        (.bip12, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
         "UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT"),
        (.bip24, Array(repeating: "abandon", count: 23).joined(separator: " ") + " art",
         "UQC020bHeiUqqyw8BB4EttblmRidKkT_hnINJ-8rZCP0L1Dw"),
        (.ton24, "exercise lawn pole excite tape shy judge episode twice crazy pudding unfold unique fatal scrub parade cover pretty payment shrimp ahead humor shoe merit",
         "UQBDJxXesUgF7mvh4aoc0aa5kjKFE1Pquz1T-u9Y_e0VQk41"),
    ]
    for (mode, phrase, want) in vectors {
        let p = Array(phrase.utf8)
        let priv = mode == .ton24 ? Array(cpuPBKDF2(tonEntropy(p), saltTonDefault, UInt32(tonIters))[0..<32])
                                  : slip10(cpuPBKDF2(p, saltMnemonic, 2048))
        let got = String(decoding: friendly(w5AccountId(ed25519Public(priv)), bounceable: false), as: UTF8.self)
        if got != want { die("SELF-TEST FAILED: \(mode.rawValue) W5 address \(got) != \(want)") }
    }
    // 3. CPU PBKDF2 on the SHA-512 instructions == CommonCrypto (incl. >128-byte keys)
    if cpu_has_sha512() != 0 {
        for i in 0..<6 {
            let a = randomBytes(40 + 20 * i), b = randomBytes(100 + 20 * i)
            var oa = [UInt8](repeating: 0, count: 64), ob = oa, o1 = oa
            let ka = a.count > 128 ? sha512(a) : a, kb = b.count > 128 ? sha512(b) : b
            let salt = i % 2 == 0 ? saltMnemonic : saltTonVersion, it = i % 2 == 0 ? 2048 : tonBasicIters
            cpu_pbkdf2_sha512_x2(ka, ka.count, kb, kb.count, salt, salt.count, UInt32(it), &oa, &ob)
            cpu_pbkdf2_sha512(ka, ka.count, salt, salt.count, UInt32(it), &o1)
            let ra = cpuPBKDF2(a, salt, UInt32(it))
            if oa != ra || o1 != ra || ob != cpuPBKDF2(b, salt, UInt32(it)) { die("SELF-TEST FAILED: CPU SHA-512 PBKDF2 mismatch") }
        }
    }
    // 4. mnemonic helpers
    let ent = randomBytes(16)
    if !isBip39Valid(bip39Indices(entropy: ent)) || !isBip39Valid(bip39Indices(entropy: randomBytes(32))) { die("SELF-TEST FAILED: BIP39 checksum") }
    if isTonValid(Array(vectors[2].1.utf8)) == false { die("SELF-TEST FAILED: TON validity") }
}

// MARK: - search loops

let gpu = GPU()
let t0 = Date()
selfTest(gpu)
let expected = pattern.reduce(1.0) { $0 * 64 / Double($1.filter { $0 }.count) }
print("GPU \(gpu.dev.name); self-test OK (GPU and CPU PBKDF2 == CommonCrypto, W5 v5r1 addresses == @ton/ton) in \(String(format: "%.1f", Date().timeIntervalSince(t0))) s")
if opt.dump == 0 && opt.bench == 0 {
    print("search: ending \"\(opt.suffix)\"\(opt.ignoreCase ? " (any case)" : "") in \(opt.bounceable ? "EQ" : "UQ") form, mode \(opt.mode.rawValue), W5 v5r1 mainnet subwallet 0, cpu workers \(opt.cpuWorkers)")
    print(String(format: "expected ~%.3g phrases; results -> %@ (phrases are never printed)", expected, opt.out))
}

var inflight = [(Job, (Job) -> Void)]()
func submit(_ j: Job, _ f: @escaping (Job) -> Void) { inflight.append((j, f)) }
func drain(keep: Int) {
    while inflight.count > keep {
        let (j, f) = inflight.removeFirst()
        j.wait()
        f(j)
    }
}
let chunks = 96

// BIP39: one GPU PBKDF2 (2048 it) per phrase
func bipBatch(_ n: Int, entLen: Int) {
    let ents = randomBytes(n * entLen)
    let kb = gpu.keysBuffer(n)
    let kp = kb.contents().bindMemory(to: UInt64.self, capacity: n * 16)
    DispatchQueue.concurrentPerform(iterations: chunks) { c in
        for i in stride(from: c, to: n, by: chunks) {
            keyBlock(phraseBytes(bip39Indices(entropy: Array(ents[i * entLen..<(i + 1) * entLen]))), into: kp + i * 16)
        }
    }
    submit(gpu.pbkdf2(keys: kb, n: n, salt: saltBlock(saltMnemonic), iters: 2048)) { job in
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            for i in stride(from: c, to: n, by: chunks) {
                finish({ bip39Indices(entropy: Array(ents[i * entLen..<(i + 1) * entLen])) }, priv: slip10(job.output(i)))
            }
        }
        shared.add(gpu: n)
    }
}

// TON standard: stage 1 = basic-seed check (390 it, keeps 1/256), stage 2 = key (100 000 it)
var survivors = [[Int]]()
func tonStage2(_ list: [[Int]]) {
    let n = list.count
    let kb = gpu.keysBuffer(n)
    let kp = kb.contents().bindMemory(to: UInt64.self, capacity: n * 16)
    DispatchQueue.concurrentPerform(iterations: chunks) { c in
        for i in stride(from: c, to: n, by: chunks) { keyBlock(tonEntropy(phraseBytes(list[i])), into: kp + i * 16) }
    }
    submit(gpu.pbkdf2(keys: kb, n: n, salt: saltBlock(saltTonDefault), iters: tonIters)) { job in
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            for i in stride(from: c, to: n, by: chunks) { finish({ list[i] }, priv: Array(job.output(i)[0..<32])) }
        }
        shared.add(gpu: n)
    }
}
func tonBatch(_ n: Int, stage2Size: Int) {
    let rnd = randomBytes(n * 33)
    var idx = [[Int]](repeating: [], count: n)
    let kb = gpu.keysBuffer(n)
    let kp = kb.contents().bindMemory(to: UInt64.self, capacity: n * 16)
    idx.withUnsafeMutableBufferPointer { ib in
        DispatchQueue.concurrentPerform(iterations: chunks) { c in
            for i in stride(from: c, to: n, by: chunks) {
                let ix = indices11(Array(rnd[i * 33..<(i + 1) * 33]), count: 24)
                ib[i] = ix
                keyBlock(tonEntropy(phraseBytes(ix)), into: kp + i * 16)
            }
        }
    }
    submit(gpu.pbkdf2(keys: kb, n: n, salt: saltBlock(saltTonVersion), iters: tonBasicIters)) { job in
        for i in 0..<n where job.firstByte(i) == 0 { survivors.append(idx[i]) }
        shared.add(s1: n)
        if survivors.count >= stage2Size {
            let list = Array(survivors.prefix(stage2Size))
            survivors.removeFirst(list.count)
            tonStage2(list)
        }
    }
}

// Thermal guard: reads the same thermal state macOS uses for its own throttling.
// serious -> CPU workers pause, critical -> GPU pauses too; both resume when it drops.
final class Thermal: @unchecked Sendable {
    var state = ProcessInfo.ThermalState.nominal
    var cpuPaused = false
    var gpuPaused = false
}
let thermal = Thermal()
func thermalName(_ s: ProcessInfo.ThermalState) -> String {
    switch s {
    case .nominal: return "nominal"
    case .fair: return "fair"
    case .serious: return "serious"
    case .critical: return "critical"
    @unknown default: return "unknown"
    }
}
do {
    let override = ProcessInfo.processInfo.environment["SEEDVANITY_THERMAL"] // for testing the pause logic
    let t = Thread {
        var last: ProcessInfo.ThermalState? = nil
        while true {
            var st = ProcessInfo.processInfo.thermalState
            if let o = override {
                st = ["nominal": .nominal, "fair": .fair, "serious": .serious, "critical": .critical][o] ?? st
            }
            thermal.state = st
            thermal.cpuPaused = st == .serious || st == .critical
            thermal.gpuPaused = st == .critical
            if st != last {
                if last != nil || st != .nominal {
                    let what = st == .critical ? ": GPU and CPU paused" : st == .serious ? ": CPU workers paused" : ": running"
                    print("[\(DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium))] thermal state \(thermalName(st))\(what)")
                }
                last = st
            }
            Thread.sleep(forTimeInterval: 2)
        }
    }
    t.start()
}

// CPU workers: PBKDF2 with the ARMv8.2 SHA-512 instructions, two phrases per call.
// 6 threads measured: +18 700/s on top of the GPU's 59 400/s, GPU speed unchanged.
let hwSHA512 = cpu_has_sha512() != 0
func hmacKey(_ pw: [UInt8]) -> [UInt8] { pw.count > 128 ? sha512(pw) : pw }
func hwPBKDF2x2(_ a: [UInt8], _ b: [UInt8], _ salt: [UInt8], _ iters: Int) -> ([UInt8], [UInt8]) {
    guard hwSHA512 else { return (cpuPBKDF2(a, salt, UInt32(iters)), cpuPBKDF2(b, salt, UInt32(iters))) }
    let ka = hmacKey(a), kb = hmacKey(b)
    var oa = [UInt8](repeating: 0, count: 64), ob = [UInt8](repeating: 0, count: 64)
    cpu_pbkdf2_sha512_x2(ka, ka.count, kb, kb.count, salt, salt.count, UInt32(iters), &oa, &ob)
    return (oa, ob)
}
for _ in 0..<opt.cpuWorkers {
    let t = Thread {
        var tonReady = [([Int], [UInt8])]() // TON phrases past the basic-seed check, waiting for a pair
        while true { autoreleasepool {
            if thermal.cpuPaused { Thread.sleep(forTimeInterval: 2); return }
            switch opt.mode {
            case .bip12, .bip24:
                let entLen = opt.mode == .bip12 ? 16 : 32
                for _ in 0..<8 {
                    let i0 = bip39Indices(entropy: randomBytes(entLen)), i1 = bip39Indices(entropy: randomBytes(entLen))
                    let (s0, s1) = hwPBKDF2x2(phraseBytes(i0), phraseBytes(i1), saltMnemonic, 2048)
                    finish({ i0 }, priv: slip10(s0), src: "cpu")
                    finish({ i1 }, priv: slip10(s1), src: "cpu")
                }
                shared.add(cpu: 16)
            case .ton24:
                for _ in 0..<64 {
                    let i0 = indices11(randomBytes(33), count: 24), i1 = indices11(randomBytes(33), count: 24)
                    let e0 = tonEntropy(phraseBytes(i0)), e1 = tonEntropy(phraseBytes(i1))
                    let (c0, c1) = hwPBKDF2x2(e0, e1, saltTonVersion, tonBasicIters)
                    if c0[0] == 0 { tonReady.append((i0, e0)) }
                    if c1[0] == 0 { tonReady.append((i1, e1)) }
                }
                while tonReady.count >= 2 {
                    let a = tonReady.removeFirst(), b = tonReady.removeFirst()
                    let (s0, s1) = hwPBKDF2x2(a.1, b.1, saltTonDefault, tonIters)
                    finish({ a.0 }, priv: Array(s0[0..<32]), src: "cpu")
                    finish({ b.0 }, priv: Array(s1[0..<32]), src: "cpu")
                    shared.add(cpu: 2)
                }
            }
        } }
    }
    // .default: measured best. .utility lands on the 4 efficiency cores (+11k/s instead of +19k/s).
    t.qualityOfService = .default
    t.start()
}

let start = Date()
var lastPrint = start, lastDone = 0, lastCpu = 0
let dumpTarget = opt.dump
// Without an explicit pool every batch leaked its Metal buffers (~20 GB per hour): the process
// was killed by macOS after ~1 h. Each iteration now drains its autoreleased objects.
while true { autoreleasepool {
        if thermal.gpuPaused {
            drain(keep: 0) // critical thermal state: let the GPU cool, keep reporting
            Thread.sleep(forTimeInterval: 2)
        } else {
            switch opt.mode {
            case .bip12: bipBatch(32768, entLen: 16)
            case .bip24: bipBatch(32768, entLen: 32)
            case .ton24: tonBatch(65536, stage2Size: dumpTarget > 0 ? dumpTarget : 16384)
            }
            drain(keep: 1)
        }

        shared.lock.lock()
        let done = shared.gpuDone + shared.cpuDone, g = shared.gpuDone, c = shared.cpuDone, dumped = shared.dumped
        shared.lock.unlock()
        let now = Date(), el = now.timeIntervalSince(start)
        if dumpTarget > 0 && dumped >= dumpTarget {
            let fd = open(opt.dumpFile, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
            let text = Array((shared.dumpLines.joined(separator: "\n") + "\n").utf8)
            _ = text.withUnsafeBufferPointer { write(fd, $0.baseAddress, text.count) }
            close(fd)
            print("dumped \(dumped) phrases with their W5 addresses to \(opt.dumpFile)")
            exit(0)
        }
        if opt.bench > 0 && el >= opt.bench {
            print(String(format: "bench %@: %.0f phrases/s (GPU %.0f/s, CPU %.0f/s) over %.0f s; a 5-character ending (2^30) would take ~%.1f h on average",
                         opt.mode.rawValue, Double(done) / el, Double(g) / el, Double(c) / el, el, pow(2, 30) / (Double(done) / el) / 3600))
            exit(0)
        }
        if opt.bench == 0 && dumpTarget == 0 && now.timeIntervalSince(lastPrint) >= 30 {
            let dt = now.timeIntervalSince(lastPrint)
            let rate = Double(done - lastDone) / dt, cpuRate = Double(c - lastCpu) / dt
            let p = 1 - exp(-Double(done) / expected)
            print(String(format: "[%@] %.2fM phrases, %.0f/s (GPU %.0f + CPU %.0f), %.1f%% of expected, chance found by now %.0f%%, avg remaining ~%.1f h, thermal %@",
                         DateFormatter.localizedString(from: now, dateStyle: .none, timeStyle: .medium),
                         Double(done) / 1e6, rate, rate - cpuRate, cpuRate, 100 * Double(done) / expected, 100 * p,
                         expected / max(rate, 1) / 3600, thermalName(thermal.state)))
            lastPrint = now
            lastDone = done
            lastCpu = c
        }
} }
