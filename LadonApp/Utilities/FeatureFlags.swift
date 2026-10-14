import Foundation

/// Central registry for build-time feature flags.
///
/// Flags here are compiled-in constants. Flipping a flag to `true` activates
/// the corresponding feature at build time; flipping to `false` makes the
/// feature fully inert — call sites must guard every externally visible
/// surface (UI entry points, network code paths, persistence) with the flag.
///
/// This file is the single source of truth so a rollback can be performed
/// by setting every flag to `false` without touching feature code.
enum FeatureFlags {

    // MARK: - Attachments (photo / video / voice)
    //
    // Multi-phase rollout (see docs/archive and session notes for spec).
    // Phase 1–7 land behind this flag. While `false`, no UI surface must
    // reference attachment APIs, no envelope type `.attachment` is produced
    // or parsed, and the blob-store endpoints remain untouched.
    //
    // Flipping to `true` is only valid after:
    //   - Phase 7 (hardening) is complete
    //   - Build is green
    //   - Server side (exit-relay blob-store) is deployed
    //   - Integration tests on physical device pass
    // 2026-05-05: Phase-7 hardening complete + blob-store live.
    // Flipped to `true` so TestFlight/Release builds expose the
    // photo/video/voice attachment UI. DEBUG override still wins.
    static var attachmentsEnabled: Bool {
        #if DEBUG
        return debugAttachmentsOverride ?? true
        #else
        return true
        #endif
    }

    #if DEBUG
    /// DEBUG-only escape hatch so `AttachmentRoundtripSelfTest` and ad-hoc
    /// developer menus can exercise the attachment pipelines without
    /// shipping a true flip. Never referenced in release builds.
    nonisolated(unsafe) static var debugAttachmentsOverride: Bool?
    #endif

    // MARK: - V2 protocol path (Phase-5 cutover — ACTIVE)
    //
    // V2 = post-quantum hybrid envelopes (ML-KEM-768, ML-DSA-65) + token-based
    // metadata-resistant routing: sealed requests in two constant-rate lanes
    // through `POST /v2/relay` (Addendum A2).
    //
    // V2 pilots (ch1, fi1, pa1, is1, is2) are LIVE since 2026-05-04.
    //
    // Phase 2 (identity bridge), Phase 3 (V2 send path), Phase 4 (V2 receive
    // polling), and Phase 5 (V2 cover traffic, full cutover) are complete.
    // V2-capable contacts are detected via PeerStoreV2 — the V1 path remains
    // as a fallback for contacts without a stored PeerHandleV2.
    //
    // Set back to `false` only to roll back the entire V2 stack on all paths.
    static let v2PathEnabled: Bool = true
}
