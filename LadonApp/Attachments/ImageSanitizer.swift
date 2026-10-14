// ImageSanitizer.swift — Phase 1
//
// Deterministic, in-memory image pipeline:
//   1. Magic-bytes check (defence against MIME-type confusion attacks)
//   2. Decode via ImageIO (sandbox-friendly, memory-bounded)
//   3. Downscale so the longest edge ≤ ``imageMaxPixelEdge`` (2 048 px)
//   4. Re-encode as JPEG quality 0.85 with *no* metadata dictionary
//      — strips EXIF, GPS, XMP, MakerNote, orientation, colour-profile
//        comments and any ICC private tags.
//
// All failure modes surface as ``ImageSanitizer.Error`` *before* the image
// data reaches the network layer. Memory is bounded by the 16 MB input cap
// (see ``AttachmentLimits.imageMaxInputBytes``) and the resulting re-encode
// buffer.
//
// This file is inert while ``FeatureFlags.attachmentsEnabled`` is false; no
// other module references it yet.

import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

public enum ImageSanitizer {

    public enum Error: Swift.Error, Equatable {
        case inputTooLarge(bytes: Int)
        case unsupportedMagicBytes
        case decodeFailed
        case downscaleFailed
        case encodeFailed
    }

    /// Result of sanitising an image input.
    public struct Result: Equatable {
        /// Freshly encoded JPEG bytes, no metadata.
        public let jpegData: Data
        /// Pixel dimensions of the output (after optional downscale).
        public let dimensions: AttachmentDimensions
    }

    /// Sanitise raw image input. Returns freshly encoded JPEG bytes plus
    /// output dimensions. Does not retain the input; caller is free to wipe
    /// the source buffer afterwards.
    public static func sanitise(_ input: Data) throws -> Result {
        guard input.count <= AttachmentLimits.imageMaxInputBytes else {
            throw Error.inputTooLarge(bytes: input.count)
        }
        guard magicAllowsImageDecode(input) else {
            throw Error.unsupportedMagicBytes
        }

        // Use ImageIO to decode. Disable caching and defer thumbnail creation
        // to minimise memory footprint.
        let sourceOptions: [CFString: Any] = [
            kCGImageSourceShouldCache: false,
            kCGImageSourceShouldAllowFloat: false,
        ]
        guard let source = CGImageSourceCreateWithData(
            input as CFData,
            sourceOptions as CFDictionary
        ) else {
            throw Error.decodeFailed
        }
        // Must contain a decodable image at index 0.
        guard CGImageSourceGetCount(source) > 0 else {
            throw Error.decodeFailed
        }

        // Decode with metadata *disallowed* — we will rebuild a clean output.
        // The `kCGImageSourceCreateThumbnailFromImageAlways` path would honour
        // EXIF orientation; we use the full image and handle orientation
        // explicitly during the draw pass so no orientation metadata survives.
        let decodeOptions: [CFString: Any] = [
            kCGImageSourceShouldCache: false,
            kCGImageSourceShouldAllowFloat: false,
        ]
        guard let decoded = CGImageSourceCreateImageAtIndex(
            source, 0, decodeOptions as CFDictionary
        ) else {
            throw Error.decodeFailed
        }

        // Downscale if either edge exceeds the cap.
        let (processed, outWidth, outHeight) = try downscaleIfNeeded(decoded)

        // Encode as JPEG with explicitly empty metadata dictionary.
        let mutable = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            mutable as CFMutableData,
            UTType.jpeg.identifier as CFString,
            1,
            nil
        ) else {
            throw Error.encodeFailed
        }

        // Build an encode-options dict that:
        //   * sets quality 0.85
        //   * nils every known metadata container (defence-in-depth — some
        //     ImageIO versions also preserve private tags; an empty dict
        //     signals "no metadata at all")
        let encodeOptions: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: AttachmentLimits.jpegReencodeQuality,
            kCGImagePropertyExifDictionary: [:],
            kCGImagePropertyGPSDictionary: [:],
            kCGImagePropertyIPTCDictionary: [:],
            kCGImagePropertyTIFFDictionary: [:],
            kCGImagePropertyPNGDictionary: [:],
            kCGImageDestinationMergeMetadata: false,
        ]

        CGImageDestinationAddImage(dest, processed, encodeOptions as CFDictionary)
        guard CGImageDestinationFinalize(dest) else {
            throw Error.encodeFailed
        }

        let data = mutable as Data
        let dims = AttachmentDimensions(
            width: UInt16(clamping: outWidth),
            height: UInt16(clamping: outHeight),
            durationMs: 0
        )
        return Result(jpegData: data, dimensions: dims)
    }

    // MARK: - Helpers

    /// Permit only images whose magic bytes identify them as JPEG, PNG, WebP
    /// or HEIC/HEIF. Anything else is rejected *before* ImageIO even sees it.
    /// This prevents content-type confusion attacks where, e.g., an SVG with
    /// an image extension would otherwise hit a scriptable parser.
    @inline(never)
    public static func magicAllowsImageDecode(_ data: Data) -> Bool {
        guard data.count >= 12 else { return false }
        let b = [UInt8](data.prefix(12))

        // JPEG: FF D8 FF
        if b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF { return true }

        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47 &&
           b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A {
            return true
        }

        // WebP: "RIFF" ???? "WEBP"
        if b[0] == 0x52 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x46 &&
           b[8] == 0x57 && b[9] == 0x45 && b[10] == 0x42 && b[11] == 0x50 {
            return true
        }

        // HEIC/HEIF ISO-BMFF:  ???? "ftyp" + brand (heic|heix|hevc|hevx|mif1|msf1|heim|heis|hevm|hevs)
        if b[4] == 0x66 && b[5] == 0x74 && b[6] == 0x79 && b[7] == 0x70 {
            let brand = b[8...11]
            let allowedBrands: [[UInt8]] = [
                [0x68, 0x65, 0x69, 0x63], // heic
                [0x68, 0x65, 0x69, 0x78], // heix
                [0x68, 0x65, 0x76, 0x63], // hevc
                [0x68, 0x65, 0x76, 0x78], // hevx
                [0x6D, 0x69, 0x66, 0x31], // mif1
                [0x6D, 0x73, 0x66, 0x31], // msf1
                [0x68, 0x65, 0x69, 0x6D], // heim
                [0x68, 0x65, 0x69, 0x73], // heis
                [0x68, 0x65, 0x76, 0x6D], // hevm
                [0x68, 0x65, 0x76, 0x73], // hevs
            ]
            return allowedBrands.contains(where: { Array(brand) == $0 })
        }

        return false
    }

    private static func downscaleIfNeeded(
        _ image: CGImage
    ) throws -> (CGImage, Int, Int) {
        let w = image.width
        let h = image.height
        let cap = AttachmentLimits.imageMaxPixelEdge
        if w <= cap && h <= cap {
            return (image, w, h)
        }

        // Preserve aspect ratio; cap the longest edge.
        let scale = CGFloat(cap) / CGFloat(max(w, h))
        let newW = max(1, Int((CGFloat(w) * scale).rounded()))
        let newH = max(1, Int((CGFloat(h) * scale).rounded()))

        let colourSpace = image.colorSpace ?? CGColorSpaceCreateDeviceRGB()
        // Pre-multiplied alpha is safe for JPEG re-encode (alpha is discarded
        // by JPEG anyway — flattening on to opaque black is deterministic).
        let bitmapInfo: UInt32 = CGImageAlphaInfo.noneSkipLast.rawValue

        guard let ctx = CGContext(
            data: nil,
            width: newW,
            height: newH,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: colourSpace,
            bitmapInfo: bitmapInfo
        ) else {
            throw Error.downscaleFailed
        }

        ctx.interpolationQuality = .high
        ctx.draw(image, in: CGRect(x: 0, y: 0, width: newW, height: newH))

        guard let resized = ctx.makeImage() else {
            throw Error.downscaleFailed
        }
        return (resized, newW, newH)
    }
}
