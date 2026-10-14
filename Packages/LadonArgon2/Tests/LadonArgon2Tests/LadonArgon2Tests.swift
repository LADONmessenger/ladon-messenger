import XCTest
@testable import LadonArgon2

final class LadonArgon2Tests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    /// RFC 9106 §5.3 — Argon2id test vector.
    func testArgon2idRFC9106Vector() throws {
        let tag = try Argon2id.hash(
            password: Data(repeating: 0x01, count: 32),
            salt: Data(repeating: 0x02, count: 16),
            secret: Data(repeating: 0x03, count: 8),
            associatedData: Data(repeating: 0x04, count: 12),
            timeCost: 3, memoryCost: 32, parallelism: 4, outputLength: 32)
        XCTAssertEqual(hex(tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    }

    /// RFC 7693 Appendix A — BLAKE2b-512("abc").
    func testBlake2bRFC7693Vector() {
        XCTAssertEqual(hex(Blake2b.hash(Data("abc".utf8))),
                       "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                       + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    }

    func testBuiltInSelfTest() {
        XCTAssertTrue(Argon2id.runSelfTest())
    }

    /// The LADON PIN parameters (m = 64 MiB, t = 3, p = 4) — and that the
    /// module really is optimised: an unoptimised build needs ~15 s here.
    func testPinParametersAreFastBecauseOptimised() throws {
        let start = Date()
        let tag = try Argon2id.hash(password: Data("123456".utf8), salt: Data(repeating: 7, count: 16),
                                    timeCost: 3, memoryCost: 65536, parallelism: 4, outputLength: 32)
        XCTAssertEqual(tag.count, 32)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5.0)
    }
}

final class LadonArgon2ReferenceTests: XCTestCase {
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    /// Same input as the LADON PIN, value computed with the unmodified
    /// P-H-C reference build (argon2_ctx, Argon2_id, version 0x13) on
    /// 13.10.2026.
    func testPinParametersMatchReferenceBuild() throws {
        let tag = try Argon2id.hash(password: Data("123456".utf8), salt: Data(repeating: 7, count: 16),
                                    timeCost: 3, memoryCost: 65536, parallelism: 4, outputLength: 32)
        XCTAssertEqual(hex(tag), "a793550bfabb360c8a440e7c0b189462d5d2867386c31d44429b6b1ecd6cc7da")
    }

    func testRejectsInvalidInput() {
        XCTAssertThrowsError(try Argon2id.hash(password: Data(), salt: Data(count: 16)))
        XCTAssertThrowsError(try Argon2id.hash(password: Data([1]), salt: Data(count: 7)))
        XCTAssertThrowsError(try Argon2id.hash(password: Data([1]), salt: Data(count: 16), memoryCost: 8, parallelism: 4))
    }
}
