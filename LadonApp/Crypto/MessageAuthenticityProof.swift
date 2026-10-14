import Foundation
import CryptoKit

/// Message Authenticity Proof using Ed25519 Signatures
/// Fix 10: Replaced fake XOR-based "Schnorr" scheme with real Ed25519 signing.
///
/// ⚠️ FIX M-25: DENIABILITY WARNING
/// Ed25519 signatures provide NON-REPUDIATION — a third party with the public
/// key can verify that the sender signed the message. This CONTRADICTS the
/// deniable authentication property of the Double Ratchet protocol.
/// Signal does NOT use long-term signatures on message content.
///
/// This proof should ONLY be used for:
/// - Opt-in authenticity verification (user explicitly requests proof)
/// - Legal/compliance contexts where non-repudiation is desired
/// - NEVER as a mandatory part of the message protocol
///
/// For standard messaging, the HMAC-based authentication in the Double Ratchet
/// already provides message integrity + authentication with deniability.
class MessageAuthenticityProof {
    
    /// Generate an authenticity proof for a message
    /// FIX MED: Returns nil on signing failure instead of hollow (signatureless) proof
    /// FIX MED-22: Proof is bound to conversationID to prevent cross-conversation replay
    /// FIX M-25: Optional previousProofHash enables proof chain integrity
    static func generateProof(
        message: Data,
        senderPrivateKey: Curve25519.Signing.PrivateKey,
        conversationID: String? = nil,
        previousProofHash: Data? = nil
    ) -> AuthenticityProof? {
        
        let timestamp = Date()
        
        // FIX MED-22: Bind signature to message hash + timestamp + conversationID
        // FIX M-24: Associated data binding — domain prefix prevents cross-protocol confusion
        var signatureInput = Data()
        signatureInput.append(Data("LadonAuthProof-v1".utf8))  // FIX M-24: Domain separator
        signatureInput.append(Data(SHA256.hash(data: message)))
        // FIX H-9: Use explicit big-endian encoding for cross-platform timestamp consistency
        let timestampBits = timestamp.timeIntervalSince1970.bitPattern.bigEndian
        let timestampBytes = withUnsafeBytes(of: timestampBits) { Data($0) }
        signatureInput.append(timestampBytes)
        signatureInput.append(senderPrivateKey.publicKey.rawRepresentation)
        // FIX MED-22: Include conversationID in signature input to prevent cross-conversation replay
        if let convID = conversationID {
            signatureInput.append(Data(SHA256.hash(data: Data(convID.utf8))))
        }
        // FIX M-25: Include previous proof hash for chain integrity
        if let prevHash = previousProofHash {
            signatureInput.append(prevHash)
        }
        
        do {
            let sig = try senderPrivateKey.signature(for: signatureInput)
            return AuthenticityProof(
                messageHash: Data(SHA256.hash(data: message)),
                timestamp: timestamp,
                senderPublicKey: senderPrivateKey.publicKey.rawRepresentation,
                signature: Data(sig),
                previousProofHash: previousProofHash
            )
        } catch {
            #if DEBUG
            SecureLogger.debug("[AuthenticityProof] ❌ Signing failed: \(error)")
            #endif
            return nil  // FIX MED: Fail explicitly — never produce hollow proof
        }
    }
    
    /// Verify authenticity proof
    /// FIX F13: maxAge parameter checks timestamp freshness (default: 5 minutes)
    /// FIX AUDIT-#80: Added conversationID parameter to match generateProof().
    /// Without this, verifyProof() ALWAYS fails when conversationID was used during signing
    /// because the reconstructed signatureInput doesn't include SHA256(conversationID).
    /// FIX AUDIT-#81: Reject future timestamps (only allow small clock-skew tolerance).
    /// FIX M-23: Proof TTL enforcement — maxAge is clamped to [10, 3600] seconds to prevent
    /// misuse with excessively long or short validity windows.
    static func verifyProof(
        proof: AuthenticityProof,
        senderPublicKey: Curve25519.Signing.PublicKey,
        expectedMessageHash: Data? = nil,
        maxAge: TimeInterval = 300,
        conversationID: String? = nil
    ) -> Bool {
        
        // FIX M-23: Clamp maxAge to reasonable bounds [10s, 3600s]
        let clampedMaxAge = min(max(maxAge, 10), 3600)
        
        // FIX F13 + AUDIT-#81: Directional timestamp check — reject future timestamps
        // beyond small clock-skew tolerance (30s), prevents pre-generated proof attacks
        let proofAge = -proof.timestamp.timeIntervalSinceNow // positive if in past
        guard proofAge >= -30 && proofAge <= clampedMaxAge else {
            return false  // Proof too old or timestamp >30s in the future
        }
        
        // Verify message hash matches if provided
        if let expectedHash = expectedMessageHash {
            guard proof.messageHash == expectedHash else {
                return false
            }
        }
        
        // Verify Ed25519 signature
        guard let signatureData = proof.signature else {
            return false  // No signature = no proof
        }
        
        // Reconstruct the signed input — must match generateProof() exactly
        var signatureInput = Data()
        signatureInput.append(Data("LadonAuthProof-v1".utf8))  // FIX M-24: Domain separator (must match generateProof)
        signatureInput.append(proof.messageHash)
        // FIX H-9: Use explicit big-endian encoding to match generateProof()
        let timestampBits = proof.timestamp.timeIntervalSince1970.bitPattern.bigEndian
        let timestampBytes = withUnsafeBytes(of: timestampBits) { Data($0) }
        signatureInput.append(timestampBytes)
        signatureInput.append(proof.senderPublicKey)
        // FIX AUDIT-#80: Include conversationID in verification to match generateProof()
        if let convID = conversationID {
            signatureInput.append(Data(SHA256.hash(data: Data(convID.utf8))))
        }
        // FIX M-25: Include previous proof hash to match generateProof() chain integrity
        if let prevHash = proof.previousProofHash {
            signatureInput.append(prevHash)
        }
        
        return senderPublicKey.isValidSignature(signatureData, for: signatureInput)
    }
}

/// Authenticity Proof Structure — Ed25519 based
/// FIX M-25: Supports optional previousProofHash for proof chain integrity
struct AuthenticityProof: Codable {
    let messageHash: Data       // SHA256 of the message content
    let timestamp: Date         // When proof was generated
    let senderPublicKey: Data   // Sender's Ed25519 public key
    let signature: Data?        // Ed25519 signature over (messageHash || timestamp || publicKey)
    /// FIX M-25: Hash of the previous proof in a chain, enabling sequential integrity verification.
    /// Nil for the first proof in a conversation or when chaining is not used.
    let previousProofHash: Data?
    
    /// Encode to binary for transmission
    /// FIX MED: Returns nil instead of empty Data on serialization failure
    func encode() -> Data? {
        let encoder = JSONEncoder()
        return try? encoder.encode(self)
    }
    
    /// Decode from binary
    static func decode(_ data: Data) -> AuthenticityProof? {
        let decoder = JSONDecoder()
        return try? decoder.decode(AuthenticityProof.self, from: data)
    }
}
