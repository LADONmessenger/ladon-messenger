import Foundation

// =============================================================================
// BLAKE2b — pure Swift (RFC 7693)
// =============================================================================
//
// Kept for the DEBUG security self-tests (SecurityFeatureTests). Checked
// against RFC 7693 Appendix A (BLAKE2b-512("abc")) in LadonArgon2Tests.
// Argon2id itself no longer uses this: it runs on the reference C
// implementation in the CArgon2 target (see Argon2id.swift).
// =============================================================================

// MARK: - Blake2b (RFC 7693)

/// Blake2b cryptographic hash function.
/// Supports variable output length (1-64 bytes).
public struct Blake2b {
    
    // Blake2b initialization vectors (first 8 primes' square roots, fractional parts)
    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]
    
    // Message word permutation schedule (sigma)
    private static let sigma: [[Int]] = [
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
        [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
        [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
        [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
        [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
        [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
        [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
        [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
        [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
        [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
        [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
    ]
    
    private var h: [UInt64] = Array(repeating: 0, count: 8)
    private var t: [UInt64] = [0, 0]       // 128-bit counter
    private var buf = Data(capacity: 128)   // Block buffer
    private let digestLength: Int
    
    /// Initialize Blake2b with output length and optional key.
    /// - Parameters:
    ///   - digestLength: Output hash length in bytes (1-64)
    ///   - key: Optional key for keyed hashing (0-64 bytes)
    init(digestLength: Int = 64, key: Data = Data()) {
        precondition(digestLength >= 1 && digestLength <= 64, "Blake2b digest must be 1-64 bytes")
        precondition(key.count <= 64, "Blake2b key must be <= 64 bytes")
        self.digestLength = digestLength
        
        // Initialize state: h = IV XOR parameter block
        // Parameter block word 0: fanout=1, depth=1, leaf_length=0,
        //   digest_length, key_length
        h = Self.iv
        h[0] ^= 0x01010000 ^ (UInt64(key.count) << 8) ^ UInt64(digestLength)
        
        // If keyed, pad key to 128 bytes and process as first block
        if !key.isEmpty {
            var paddedKey = Data(count: 128)
            paddedKey.replaceSubrange(0..<key.count, with: key)
            update(paddedKey)
            // FIX R16-A5: Wipe padded key copy after feeding into Blake2b
            paddedKey.securelyWipe()
        }
    }
    
    /// Feed data into the hash.
    mutating func update(_ data: Data) {
        var offset = 0
        
        while offset < data.count {
            // If buffer is full (128 bytes), compress it
            if buf.count == 128 {
                incrementCounter(by: 128)
                compress(block: buf, isFinal: false)
                buf.removeAll(keepingCapacity: true)
            }
            
            let remaining = 128 - buf.count
            let take = min(remaining, data.count - offset)
            buf.append(data[data.startIndex + offset ..< data.startIndex + offset + take])
            offset += take
        }
    }
    
    /// Finalize and return the hash.
    mutating func finalize() -> Data {
        // Process remaining bytes (the last block)
        incrementCounter(by: UInt64(buf.count))
        
        // Pad buffer to 128 bytes with zeros
        while buf.count < 128 {
            buf.append(0)
        }
        
        compress(block: buf, isFinal: true)
        
        // Produce output: first `digestLength` bytes of h (little-endian)
        var output = Data(capacity: digestLength)
        for i in 0 ..< 8 {
            var word = h[i].littleEndian
            let wordData = withUnsafeBytes(of: &word) { Data($0) }
            output.append(wordData)
        }
        return output.prefix(digestLength)
    }
    
    /// Convenience: hash data in one call.
    public static func hash(_ data: Data, digestLength: Int = 64) -> Data {
        var hasher = Blake2b(digestLength: digestLength)
        hasher.update(data)
        return hasher.finalize()
    }
    
    // MARK: - Private
    
    private mutating func incrementCounter(by n: UInt64) {
        t[0] = t[0] &+ n
        if t[0] < n { t[1] = t[1] &+ 1 }  // FIX H-13: Counter carry was never assigned
    }
    
    /// Blake2b compression function F.
    private mutating func compress(block: Data, isFinal: Bool) {
        // Parse message block into 16 words (little-endian)
        var m = [UInt64](repeating: 0, count: 16)
        block.withUnsafeBytes { ptr in
            for i in 0..<16 {
                // FIX MUC-2: loadUnaligned — Data buffer has no alignment guarantee
                m[i] = ptr.loadUnaligned(fromByteOffset: i * 8, as: UInt64.self).littleEndian
            }
        }
        
        // Initialize working vector v
        var v = [UInt64](repeating: 0, count: 16)
        v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3] = h[3]
        v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7] = h[7]
        v[8]  = Self.iv[0]; v[9]  = Self.iv[1]
        v[10] = Self.iv[2]; v[11] = Self.iv[3]
        v[12] = Self.iv[4] ^ t[0]   // Low counter
        v[13] = Self.iv[5] ^ t[1]   // High counter
        v[14] = isFinal ? ~Self.iv[6] : Self.iv[6]  // Finalization flag
        v[15] = Self.iv[7]
        
        // 12 rounds of mixing
        for round in 0..<12 {
            let s = Self.sigma[round]
            
            // Column step
            Self.mix(&v, 0, 4,  8, 12, m[s[0]],  m[s[1]])
            Self.mix(&v, 1, 5,  9, 13, m[s[2]],  m[s[3]])
            Self.mix(&v, 2, 6, 10, 14, m[s[4]],  m[s[5]])
            Self.mix(&v, 3, 7, 11, 15, m[s[6]],  m[s[7]])
            
            // Diagonal step
            Self.mix(&v, 0, 5, 10, 15, m[s[8]],  m[s[9]])
            Self.mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            Self.mix(&v, 2, 7,  8, 13, m[s[12]], m[s[13]])
            Self.mix(&v, 3, 4,  9, 14, m[s[14]], m[s[15]])
        }
        
        // Update state
        for i in 0..<8 {
            h[i] = h[i] ^ v[i] ^ v[i + 8]
        }
    }
    
    /// Blake2b mixing function G.
    @inline(__always)
    private static func mix(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotatedRight(by: 16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotatedRight(by: 63)
    }
}

// MARK: - UInt64 Rotation Extension

private extension UInt64 {
    @inline(__always)
    func rotatedRight(by n: Int) -> UInt64 {
        return (self >> n) | (self << (64 - n))
    }
}
