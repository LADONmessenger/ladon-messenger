//
//  WireUtilV2.swift
//  Ladon — small helpers for big-endian integers and slicing Data buffers.
//

import Foundation

/// Big-endian u16 encoder.
@inline(__always)
func u16BE(_ value: UInt16) -> Data {
    var be = value.bigEndian
    return withUnsafeBytes(of: &be) { Data($0) }
}

/// Big-endian u32 encoder.
@inline(__always)
func u32BE(_ value: UInt32) -> Data {
    var be = value.bigEndian
    return withUnsafeBytes(of: &be) { Data($0) }
}

/// Big-endian u64 encoder.
@inline(__always)
func u64BE(_ value: UInt64) -> Data {
    var be = value.bigEndian
    return withUnsafeBytes(of: &be) { Data($0) }
}

/// Read a big-endian u16 at the given absolute offset.
@inline(__always)
func readU16BE(_ data: Data, at offset: Int) -> UInt16 {
    let lo = data.startIndex + offset
    let hi = lo + 2
    var v: UInt16 = 0
    data.subdata(in: lo..<hi).withUnsafeBytes { ptr in
        v = ptr.load(as: UInt16.self).bigEndian
    }
    return v
}

/// Read a big-endian u32 at the given absolute offset.
@inline(__always)
func readU32BE(_ data: Data, at offset: Int) -> UInt32 {
    let lo = data.startIndex + offset
    let hi = lo + 4
    var v: UInt32 = 0
    data.subdata(in: lo..<hi).withUnsafeBytes { ptr in
        v = ptr.load(as: UInt32.self).bigEndian
    }
    return v
}

/// Read a big-endian u64 at the given absolute offset.
@inline(__always)
func readU64BE(_ data: Data, at offset: Int) -> UInt64 {
    let lo = data.startIndex + offset
    let hi = lo + 8
    var v: UInt64 = 0
    data.subdata(in: lo..<hi).withUnsafeBytes { ptr in
        v = ptr.load(as: UInt64.self).bigEndian
    }
    return v
}

/// Slice a sub-Data of fixed length starting at `offset` (absolute).
@inline(__always)
func subdata(_ data: Data, _ offset: Int, _ length: Int) -> Data {
    let lo = data.startIndex + offset
    let hi = lo + length
    return data.subdata(in: lo..<hi)
}

/// Generate `n` cryptographically random bytes.
@inline(__always)
func randomBytes(_ n: Int) -> Data {
    var b = Data(count: n)
    let status = b.withUnsafeMutableBytes { ptr -> Int32 in
        SecRandomCopyBytes(kSecRandomDefault, ptr.count, ptr.baseAddress!)
    }
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed (\(status))")
    return b
}
