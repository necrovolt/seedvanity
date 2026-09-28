// Stage 1: correctness + throughput of PBKDF2-HMAC-SHA512 on the Mac GPU.
// Build: swiftc -O bench.swift -o bench && ./bench [seconds]
import CommonCrypto
import Foundation
import Metal

setvbuf(stdout, nil, _IONBF, 0)

// ---------- helpers ----------
func beWords(_ b: [UInt8]) -> [UInt64] {
    stride(from: 0, to: b.count, by: 8).map { i in b[i..<i + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } }
}
func beBytes(_ w: ArraySlice<UInt64>) -> [UInt8] {
    w.flatMap { x in (0..<8).map { UInt8(truncatingIfNeeded: x >> (56 - 8 * $0)) } }
}
func sha512(_ b: [UInt8]) -> [UInt8] {
    var d = [UInt8](repeating: 0, count: 64)
    CC_SHA512(b, CC_LONG(b.count), &d)
    return d
}
// HMAC key zero-padded to one 128-byte block (long keys pre-hashed, as HMAC requires)
func keyBlock(_ pw: [UInt8]) -> [UInt64] {
    var k = pw.count > 128 ? sha512(pw) : pw
    k += [UInt8](repeating: 0, count: 128 - k.count)
    return beWords(k)
}
// second block of the first inner hash: salt || INT(1) || 0x80 || 0.. || bitlen
func saltBlock(_ salt: [UInt8]) -> [UInt64] {
    precondition(salt.count <= 107)
    var b = salt + [0, 0, 0, 1, 0x80]
    b += [UInt8](repeating: 0, count: 120 - b.count)
    let bits = UInt64(128 + salt.count + 4) * 8
    b += (0..<8).map { UInt8(truncatingIfNeeded: bits >> (56 - 8 * $0)) }
    return beWords(b)
}
func cpuPBKDF2(_ pw: [UInt8], _ salt: [UInt8], _ iters: UInt32) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: 64)
    let p = pw.map { CChar(bitPattern: $0) }
    let rc = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), p, p.count, salt, salt.count,
                                  CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), iters, &out, 64)
    precondition(rc == 0)
    return out
}
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

// ---------- Metal ----------
let consts = try! String(contentsOfFile: "sha512_consts.h", encoding: .utf8)
let body = try! String(contentsOfFile: "pbkdf2.metal", encoding: .utf8)
let src = body.replacingOccurrences(of: "using namespace metal;", with: "using namespace metal;\n" + consts)
let dev = MTLCreateSystemDefaultDevice()!
let t0 = Date()
let lib = try! dev.makeLibrary(source: src, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "pbkdf2_sha512")!)
let queue = dev.makeCommandQueue()!
print("GPU: \(dev.name), compile \(String(format: "%.1f", Date().timeIntervalSince(t0))) s, maxThreads/tg \(pso.maxTotalThreadsPerThreadgroup), simd \(pso.threadExecutionWidth)")

func gpu(_ keys: [UInt64], _ salt: [UInt64], _ iters: UInt32, tg: Int) -> ([UInt64], Double) {
    let n = keys.count / 16
    let kb = dev.makeBuffer(bytes: keys, length: keys.count * 8, options: .storageModeShared)!
    let sb = dev.makeBuffer(bytes: salt, length: 128, options: .storageModeShared)!
    var it = iters
    let ob = dev.makeBuffer(length: n * 64, options: .storageModeShared)!
    let cb = queue.makeCommandBuffer()!
    let enc = cb.makeComputeCommandEncoder()!
    enc.setComputePipelineState(pso)
    enc.setBuffer(kb, offset: 0, index: 0)
    enc.setBuffer(sb, offset: 0, index: 1)
    enc.setBytes(&it, length: 4, index: 2)
    enc.setBuffer(ob, offset: 0, index: 3)
    enc.dispatchThreads(MTLSize(width: n, height: 1, depth: 1),
                        threadsPerThreadgroup: MTLSize(width: min(tg, pso.maxTotalThreadsPerThreadgroup), height: 1, depth: 1))
    enc.endEncoding()
    cb.commit()
    cb.waitUntilCompleted()
    if let e = cb.error { fatalError("GPU error: \(e)") }
    let p = ob.contents().bindMemory(to: UInt64.self, capacity: n * 8)
    return (Array(UnsafeBufferPointer(start: p, count: n * 8)), cb.gpuEndTime - cb.gpuStartTime)
}

func randomPw(_ len: Int) -> [UInt8] {
    let alphabet = Array("abcdefghijklmnopqrstuvwxyz ".utf8)
    return (0..<len).map { _ in alphabet.randomElement()! }
}

// ---------- 1. correctness ----------
var fails = 0
func check(_ name: String, pws: [[UInt8]], salt: [UInt8], iters: UInt32) {
    let (out, _) = gpu(pws.flatMap(keyBlock), saltBlock(salt), iters, tg: 64)
    var bad = 0
    for (i, pw) in pws.enumerated() where beBytes(out[i * 8..<i * 8 + 8]) != cpuPBKDF2(pw, salt, iters) { bad += 1 }
    fails += bad
    print("check \(name): \(pws.count - bad)/\(pws.count) match CommonCrypto")
}
let bipVector = Array("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8)
do {
    let (out, _) = gpu(keyBlock(bipVector), saltBlock(Array("mnemonic".utf8)), 2048, tg: 64)
    let got = hex(beBytes(out[0..<8]))
    let ok = got == "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    if !ok { fails += 1 }
    print("BIP39 test vector (abandon x11 about): \(ok ? "OK" : "MISMATCH " + got)")
}
check("BIP39 12/24-word lengths (1..215 bytes, incl. >128 pre-hash), 2048 it",
      pws: (0..<512).map { randomPw(1 + $0 % 215) }, salt: Array("mnemonic".utf8), iters: 2048)
check("TON basic-seed style (64-byte key, 'TON seed version', 390 it)",
      pws: (0..<128).map { _ in (0..<64).map { _ in UInt8.random(in: 0...255) } }, salt: Array("TON seed version".utf8), iters: 390)
check("iters = 1 and 2", pws: (0..<64).map { randomPw(80 + $0) }, salt: Array("mnemonic".utf8), iters: 1)
check("iters = 2", pws: (0..<64).map { randomPw(80 + $0) }, salt: Array("mnemonic".utf8), iters: 2)
if fails > 0 { print("CORRECTNESS FAILED (\(fails)), no benchmark"); exit(1) }

// ---------- 2. throughput ----------
let salt = saltBlock(Array("mnemonic".utf8))
func keysFor(_ n: Int) -> [UInt64] { (0..<n).flatMap { _ in keyBlock(randomPw(80)) } }
var best = (tg: 64, rate: 0.0)
let probeKeys = keysFor(16384)
_ = gpu(probeKeys, salt, 2048, tg: 64) // warm-up
for tg in [32, 64, 128, 256, 512, 1024] where tg <= pso.maxTotalThreadsPerThreadgroup {
    let (_, t) = gpu(probeKeys, salt, 2048, tg: tg)
    let r = 16384 / t
    print(String(format: "tg %4d: %8.0f PBKDF2/s (batch %.2f s)", tg, r, t))
    if r > best.rate { best = (tg, r) }
}
var n = 16384
while n < 1 << 20 {
    let (_, t) = gpu(keysFor(n * 2), salt, 2048, tg: best.tg)
    print(String(format: "batch %7d: %8.0f PBKDF2/s (%.2f s)", n * 2, Double(n * 2) / t, t))
    if t > 1.0 { break }
    n *= 2
}
let secs = Double(CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "20") ?? 20
let keys = keysFor(n)
var done = 0
let start = Date()
while Date().timeIntervalSince(start) < secs {
    _ = gpu(keys, salt, 2048, tg: best.tg)
    done += n
}
let wall = Date().timeIntervalSince(start)
let rate = Double(done) / wall
print(String(format: "SUSTAINED %.0f s: %.0f PBKDF2-2048/s (tg %d, batch %d) = %.1f M HMAC-SHA512/s", wall, rate, best.tg, n, rate * 2049 / 1e6))
print(String(format: "a 5-character ending (2^30) would take ~%.1f h on the GPU alone", pow(2, 30) / rate / 3600))
