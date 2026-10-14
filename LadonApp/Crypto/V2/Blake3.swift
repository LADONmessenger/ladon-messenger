//
//  Blake3.swift
//  Ladon — Swift wrapper around the BLAKE3 C reference implementation.
//
//  Mirrors `relay-core-v2/src/hash.rs` — byte-identical output is REQUIRED for
//  cross-language interoperability of Token-IDs, Exit-IDs and HSig prehash.
//

import Foundation

/// Thin Swift wrapper around the BLAKE3 reference C implementation
/// (LadonApp/Crypto/blake3/, official BLAKE3-team source v1.5.5).
enum Blake3 {
    /// Standard BLAKE3 hash. Returns the requested number of bytes (default 32).
    static func hash(_ data: Data, outputLength: Int = 32) -> Data {
        precondition(outputLength > 0, "outputLength must be > 0")
        var hasher = blake3_hasher()
        blake3_hasher_init(&hasher)
        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            if let base = ptr.baseAddress, ptr.count > 0 {
                blake3_hasher_update(&hasher, base, ptr.count)
            }
        }
        var out = Data(count: outputLength)
        out.withUnsafeMutableBytes { (mptr: UnsafeMutableRawBufferPointer) in
            blake3_hasher_finalize(&hasher, mptr.baseAddress!.assumingMemoryBound(to: UInt8.self), outputLength)
        }
        return out
    }

    /// Streaming variant for callers that want to feed multiple chunks.
    final class Hasher {
        private var state = blake3_hasher()

        init() {
            blake3_hasher_init(&state)
        }

        func update(_ data: Data) {
            data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                if let base = ptr.baseAddress, ptr.count > 0 {
                    blake3_hasher_update(&state, base, ptr.count)
                }
            }
        }

        func update(_ bytes: UnsafeRawBufferPointer) {
            if let base = bytes.baseAddress, bytes.count > 0 {
                blake3_hasher_update(&state, base, bytes.count)
            }
        }

        func finalize(outputLength: Int = 32) -> Data {
            var out = Data(count: outputLength)
            out.withUnsafeMutableBytes { (mptr: UnsafeMutableRawBufferPointer) in
                blake3_hasher_finalize(&state, mptr.baseAddress!.assumingMemoryBound(to: UInt8.self), outputLength)
            }
            return out
        }
    }
}
