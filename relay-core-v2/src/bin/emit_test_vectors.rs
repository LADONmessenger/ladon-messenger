//! Cross-language test-vector emitter.
//!
//! Run: `cargo run --bin emit_test_vectors --manifest-path relay-core-v2/Cargo.toml`
//!
//! Emits a JSON document to stdout with deterministic hex strings derived from
//! fixed inputs. The Swift `LadonV2CrossLangVectors` hardcodes the same hex
//! strings and compares them byte-for-byte.
//!
//! Fixed inputs (chosen for clarity, NOT for cryptographic randomness):
//!   * recipient_id      = 0xAA × 32
//!   * exit_id           = 0xBB × 16
//!   * recipient_hsig_pk = 0x22 × 1,984
//!   * recipient_hkem_pk = 0x33 × 1,216
//!   * bundle_id         = 0x44 × 16
//!   * bundle_hsig       = 0x55 × 3,373
//!   * published_at      = 1,700,000,000
//!   * delivery_key K    = 0x5A × 32
//!   * sent_at           = 1,700,000,000
//!   * envelope_id       = 0xE1 × 16
//!   * fetch_ts          = 1,700,000,000
//!   * fetch_ack         = 0xEE × 16 (fetch pre-image also uses exit_id above)
//!   * tagged-sig message = "ladon-vector"
//!
//! All multi-byte integers are big-endian.

use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hash::{delivery_verifier, exit_delivery_key, exit_id_from_hkem_pk};
use ladon_relay_core_v2::hsig::{
    prehash_tagged, HSIG_USECASE_BUNDLE, HSIG_USECASE_FETCH, HSIG_USECASE_INNER_SENDER,
    HSIG_USECASE_PAIRING, HSIG_USECASE_PUSH_REGISTER,
};
use ladon_relay_core_v2::ids::{BundleId, EnvelopeId, ExitId, RecipientId};
use ladon_relay_core_v2::wire::sealed::{self, Kind};
use ladon_relay_core_v2::wire::{Bundle, OuterPlaintext};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    // ---- Fixed inputs -------------------------------------------------------
    let rid_bytes = [0xAAu8; RECIPIENT_ID_LEN];
    let exit_bytes = [0xBBu8; EXIT_ID_LEN];
    let rid = RecipientId(rid_bytes);
    let exit = ExitId(exit_bytes);
    let published_at: u64 = 1_700_000_000;
    let delivery_key = [0x5Au8; DELIVERY_KEY_LEN];

    // ---- Delivery key derivation (A1 §2) -----------------------------------
    let k_x = exit_delivery_key(&delivery_key, &exit);
    let v_x = delivery_verifier(&k_x);

    // ---- ExitId derivation --------------------------------------------------
    let exit_pk_input = vec![0x77u8; HKEM_PK_LEN];
    let derived_exit_id = exit_id_from_hkem_pk(&exit_pk_input);

    // ---- Delivery bundle (A1 §3.2) -----------------------------------------
    // Structure only: rid is the fixed 0xAA input, not SHA-256 of the fixed
    // pk, so this bundle would fail validate_structure — it is a layout vector.
    let bundle = Bundle {
        version: RELAY_PROTOCOL_VERSION,
        recipient_id: rid,
        recipient_hsig_pk: vec![0x22u8; HSIG_PK_LEN],
        recipient_hkem_pk: vec![0x33u8; HKEM_PK_LEN],
        bundle_id: BundleId([0x44u8; 16]),
        published_at,
        exit_id: exit,
        verifier: v_x,
        bundle_hsig: vec![0x55u8; HSIG_SIG_LEN],
    };
    let bundle_bytes = bundle.encode();
    let bundle_signing_input = bundle.signing_input();

    // ---- Sealed ENQUEUE body header (A2 §4.1, 88 B) -------------------------
    // rid ‖ K_X ‖ sent_at ‖ envelope_id: the outer-plaintext layout without
    // its (zero) flags byte, exactly as the exit rebuilds it.
    let enqueue_header = OuterPlaintext {
        flags: 0,
        recipient_id: rid,
        delivery_key: k_x,
        sent_at: 1_700_000_000,
        envelope_id: EnvelopeId([0xE1u8; ENVELOPE_ID_LEN]),
        inner_envelope: Vec::new(),
    }
    .encode()[1..]
        .to_vec();

    // ---- Inner AAD (unchanged) ----------------------------------------------
    let inner_aad = {
        let mut a = Vec::with_capacity(AAD_INNER_V1.len() + 1 + RECIPIENT_ID_LEN);
        a.extend_from_slice(AAD_INNER_V1);
        a.push(INNER_AAD_VERSION);
        a.extend_from_slice(&rid_bytes);
        a
    };

    // ---- Fetch pre-images ---------------------------------------------------
    let fetch_ts: u64 = 1_700_000_000;
    let fetch_ack = [0xEEu8; FETCH_BATCH_ID_LEN];
    let fetch_ack_preimage = {
        // SRV-13: "L1-FetchAck-v2" || exit_id || rid || ts_be || ack, with
        // the fixed exit_id input (0xBB × 16).
        let mut m = Vec::with_capacity(
            DOMAIN_FETCH_ACK_AUTH.len() + EXIT_ID_LEN + RECIPIENT_ID_LEN + 8 + FETCH_BATCH_ID_LEN);
        m.extend_from_slice(DOMAIN_FETCH_ACK_AUTH);
        m.extend_from_slice(&exit_bytes);
        m.extend_from_slice(&rid_bytes);
        m.extend_from_slice(&fetch_ts.to_be_bytes());
        m.extend_from_slice(&fetch_ack);
        m
    };

    // ---- Tagged HSig pre-hash (A1 §10) -------------------------------------
    let msg = b"ladon-vector";
    let pre_bundle = prehash_tagged(HSIG_USECASE_BUNDLE, msg);
    let pre_fetch = prehash_tagged(HSIG_USECASE_FETCH, msg);
    let pre_push = prehash_tagged(HSIG_USECASE_PUSH_REGISTER, msg);
    let pre_inner = prehash_tagged(HSIG_USECASE_INNER_SENDER, msg);
    let pre_pairing = prehash_tagged(HSIG_USECASE_PAIRING, msg);

    // ---- BLAKE3 KAT for empty + "abc" --------------------------------------
    let blake3_empty = blake3::hash(b"").as_bytes().to_vec();
    let blake3_abc = blake3::hash(b"abc").as_bytes().to_vec();

    // ---- Sealed request / response (A2 §4) ---------------------------------
    // Fixed HKEM secret, HKEM ciphertext and nonces stand in for the random
    // ones; everything after HKEM must match byte for byte in Swift.
    let sealed_v = sealed::seal_for_test_vectors(
        &[0x33u8; 32],
        &[0x77u8; HKEM_CT_LEN],
        &[0x01u8; 12],
        &[0x02u8; 12],
        &[0x42u8; 16],
        Kind::Fetch,
        b"ladon-sealed",
        sealed::status::OK,
        1_700_000_000,
        b"ok",
    )
    .expect("sealed vector");

    // ---- Emit ---------------------------------------------------------------
    println!("{{");
    println!(r#"  "format_version": 2,"#);
    println!(r#"  "relay_protocol_version": {},"#, RELAY_PROTOCOL_VERSION);
    println!(r#"  "blake3_empty": "{}","#, hex(&blake3_empty));
    println!(r#"  "blake3_abc": "{}","#, hex(&blake3_abc));
    println!(r#"  "exit_id_from_pk_77": "{}","#, hex(derived_exit_id.as_bytes()));
    println!(r#"  "exit_delivery_key": "{}","#, hex(&k_x));
    println!(r#"  "delivery_verifier": "{}","#, hex(&v_x));
    println!(r#"  "bundle_len": {},"#, bundle_bytes.len());
    println!(r#"  "bundle_blake3": "{}","#, hex(blake3::hash(&bundle_bytes).as_bytes()));
    println!(r#"  "bundle_signing_input_blake3": "{}","#, hex(blake3::hash(&bundle_signing_input).as_bytes()));
    println!(r#"  "enqueue_body_header": "{}","#, hex(&enqueue_header));
    println!(r#"  "enqueue_body_header_len": {},"#, enqueue_header.len());
    println!(r#"  "inner_aad": "{}","#, hex(&inner_aad));
    println!(r#"  "inner_aad_len": {},"#, inner_aad.len());
    println!(r#"  "fetch_ack_preimage": "{}","#, hex(&fetch_ack_preimage));
    println!(r#"  "fetch_ack_preimage_len": {},"#, fetch_ack_preimage.len());
    println!(r#"  "prehash_tagged_bundle": "{}","#, hex(&pre_bundle));
    println!(r#"  "prehash_tagged_fetch": "{}","#, hex(&pre_fetch));
    println!(r#"  "prehash_tagged_push_register": "{}","#, hex(&pre_push));
    println!(r#"  "prehash_tagged_inner_sender": "{}","#, hex(&pre_inner));
    println!(r#"  "prehash_tagged_pairing": "{}","#, hex(&pre_pairing));
    println!(r#"  "sealed_k_req": "{}","#, hex(&sealed_v.k_req));
    println!(r#"  "sealed_k_resp": "{}","#, hex(&sealed_v.k_resp));
    println!(r#"  "sealed_request_len": {},"#, sealed_v.request.len());
    println!(r#"  "sealed_request_blake3": "{}","#, hex(blake3::hash(&sealed_v.request).as_bytes()));
    println!(r#"  "sealed_response_len": {},"#, sealed_v.response.len());
    println!(r#"  "sealed_response_blake3": "{}""#, hex(blake3::hash(&sealed_v.response).as_bytes()));
    println!("}}");
}
