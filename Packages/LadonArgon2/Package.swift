// swift-tools-version:5.9
//
// Argon2id (RFC 9106, reference C implementation) and Blake2b (RFC 7693,
// Swift), outside the app target so they are always compiled with
// optimisation: in the app's Debug build (-Onone) the former pure-Swift
// Argon2id took ~15 s on a Mac for m = 64 MiB / t = 3 / p = 4 and far longer
// on an iPhone (13.10.2026). The parameters are unchanged.
import PackageDescription

let package = Package(
    name: "LadonArgon2",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "LadonArgon2", targets: ["LadonArgon2"]),
    ],
    targets: [
        // Reference Argon2 by its authors (P-H-C/phc-winner-argon2, commit
        // f57e61e19229e23c4445b85494dbf7c07de721cb, CC0 / Apache-2.0 — see
        // Sources/CArgon2/LICENSE), portable "ref" variant. -O3 as in the
        // upstream Makefile, in every configuration.
        .target(
            name: "CArgon2",
            exclude: ["LICENSE"],
            cSettings: [.unsafeFlags(["-O3"])]
        ),
        .target(
            name: "LadonArgon2",
            dependencies: ["CArgon2"],
            swiftSettings: [.unsafeFlags(["-O"])]
        ),
        .testTarget(
            name: "LadonArgon2Tests",
            dependencies: ["LadonArgon2"]
        ),
    ]
)
