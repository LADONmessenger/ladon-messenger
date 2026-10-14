//
//  DeliveryKeyV2.swift
//  Ladon — delivery-key derivation (Addendum A1 §2).
//
//  Every user holds one secret delivery key K (32 B) and hands it only to
//  contacts (pairing code v4, START/KEY control messages). For each exit a
//  sender derives the exit delivery key K_X and presents it inside the sealed
//  outer plaintext; the exit compares SHA-256 of it with the verifier V_X the
//  recipient published in its signed bundle.
//
//      K_X = HKDF-SHA256(salt = "L1-DeliverSalt-v1", ikm = K,
//                        info = "L1-Deliver-v1" || exit_id, L = 32)
//      V_X = SHA-256("L1-DeliverVerify-v1" || K_X)
//
//  Mirrors `exit_delivery_key` / `delivery_verifier` in
//  `relay-core-v2/src/hash.rs`; covered by the cross-language vectors.
//  K_X is exit-bound: what one exit sees cannot be presented at another.
//

import Foundation
import CryptoKit

enum DeliveryKeyV2 {

    /// K_X for `exitId`. `deliveryKey` must be exactly 32 bytes.
    static func exitDeliveryKey(_ deliveryKey: Data, exitId: ExitIdV2) throws -> Data {
        guard deliveryKey.count == LadonV2.deliveryKeyLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.deliveryKeyLen, got: deliveryKey.count)
        }
        var info = Data(capacity: LadonV2.domainDeliverInfo.count + LadonV2.exitIdLen)
        info.append(LadonV2.domainDeliverInfo)
        info.append(exitId.bytes)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: deliveryKey),
            salt: LadonV2.domainDeliverSalt,
            info: info,
            outputByteCount: LadonV2.deliveryKeyLen
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// V_X for an exit delivery key.
    static func verifier(exitDeliveryKey kx: Data) -> Data {
        var h = SHA256()
        h.update(data: LadonV2.domainDeliverVerify)
        h.update(data: kx)
        return Data(h.finalize())
    }
}
