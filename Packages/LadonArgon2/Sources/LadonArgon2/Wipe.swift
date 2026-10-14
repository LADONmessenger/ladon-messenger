import Foundation

extension Data {
    /// Zero the buffer in place before it is released. Same intent as the
    /// app's `securelyWipe()` (MemoryProtector), which this module cannot see;
    /// `memset_s` is never optimised away. Mutating through the unsafe
    /// pointer makes the storage unique first, so the bytes zeroed are the
    /// ones this value owns.
    mutating func securelyWipe() {
        let n = count
        guard n > 0 else { return }
        withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress { _ = memset_s(base, n, 0, n) }
        }
    }
}
