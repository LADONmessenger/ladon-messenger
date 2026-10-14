// ThumbnailGenerator.swift — Phase 1
//
// Produces a small thumbnail (256 px longest edge) of an already-sanitised
// image. Uses ImageIO's `CGImageSourceCreateThumbnailAtIndex` which
// internally downscales; we then re-encode as JPEG because iOS ImageIO does
// not ship a WebP encoder in all SDK versions we target.
//
// The plaintext thumbnail bytes returned here are *not yet encrypted or
// padded*. Phase 2 seals them with the attachment master seed and pads the
// ciphertext to exactly ``AttachmentDescriptor.sealedThumbnailByteCount``
// bytes so the envelope field is a fixed size regardless of input.
//
// Inert while ``FeatureFlags.attachmentsEnabled`` is false.

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

public enum ThumbnailGenerator {

    public enum Error: Swift.Error, Equatable {
        case decodeFailed
        case encodeFailed
    }

    /// Generate a JPEG thumbnail (256 px longest edge) from a sanitised
    /// JPEG input. The output is constrained to stay at or below the soft
    /// target of ``AttachmentLimits.thumbnailTargetPlaintextBytes`` by
    /// progressively lowering JPEG quality. A hard ceiling below 2 KB is
    /// acceptable for our padding envelope of 4 096 bytes.
    public static func thumbnailJPEG(from jpegData: Data) throws -> Data {
        let sourceOptions: [CFString: Any] = [
            kCGImageSourceShouldCache: false,
            kCGImageSourceShouldAllowFloat: false,
        ]
        guard let source = CGImageSourceCreateWithData(
            jpegData as CFData,
            sourceOptions as CFDictionary
        ) else {
            throw Error.decodeFailed
        }

        // Hard ceiling for the encoded thumbnail (must fit the 4096-byte
        // slot with 64 B reserved for AEAD overhead).
        let hardCeiling = AttachmentDescriptor.sealedThumbnailByteCount - 64

        // Fallback ladder: start at the full 256 px edge, fall back to
        // smaller thumbnails if even low-quality JPEG still exceeds the
        // hard ceiling. Very noisy / high-detail photos can produce a
        // thumbnail > 4 KB even at q=0.30.
        let edgeLadder: [Int] = [
            AttachmentLimits.thumbnailEdgePixels,   // 256
            200,
            160,
            128,
        ]
        let qualityLadder: [CGFloat] = [0.70, 0.55, 0.40, 0.30, 0.22, 0.15]

        for edge in edgeLadder {
            let thumbnailOptions: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: false,
                kCGImageSourceThumbnailMaxPixelSize: edge,
                kCGImageSourceShouldCache: false,
                kCGImageSourceShouldAllowFloat: false,
            ]
            guard let thumbCG = CGImageSourceCreateThumbnailAtIndex(
                source, 0, thumbnailOptions as CFDictionary
            ) else {
                continue
            }

            for q in qualityLadder {
                guard let data = encodeJPEG(thumbCG, quality: q) else { continue }
                // First acceptable result at this edge: if it fits within
                // the soft target, return immediately (best quality).
                if data.count <= AttachmentLimits.thumbnailTargetPlaintextBytes {
                    return data
                }
                // If it at least fits the hard ceiling, we can use it as a
                // fallback — take the highest quality that fits.
                if data.count <= hardCeiling {
                    return data
                }
            }
        }

        // Nothing in the ladder produced a small-enough encode. Give up.
        throw Error.encodeFailed
    }

    private static func encodeJPEG(_ image: CGImage, quality: CGFloat) -> Data? {
        let mutable = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            mutable as CFMutableData,
            UTType.jpeg.identifier as CFString,
            1,
            nil
        ) else { return nil }
        let options: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: quality,
            kCGImagePropertyExifDictionary: [:],
            kCGImagePropertyGPSDictionary: [:],
            kCGImagePropertyIPTCDictionary: [:],
            kCGImagePropertyTIFFDictionary: [:],
        ]
        CGImageDestinationAddImage(dest, image, options as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return mutable as Data
    }
}
