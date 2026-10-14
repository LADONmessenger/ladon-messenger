//! Generate per-host secret material for a Ladon V2 Pilot relay.
//!
//! Outputs (stdout, JSON):
//!   - hkem_pk_hex    (1216 hex chars; 608 bytes)  -- not used, informational
//!   - exit_id_hex    (32 hex chars;  16 bytes)    -- BLAKE3(hkem_pk)[..16]
//!   - s2s_hmac_key_hex (64 hex chars; 32 bytes)
//!
//! Side effect: writes the HKEM keyfile (raw layout) to the path given as
//! the first CLI arg, mode 0600.
//!
//! Keyfile layout (raw, no framing):
//!     X25519_SK   (32 bytes)
//!     KYBER768_SK (2400 bytes)
//!     KYBER768_PK (1184 bytes)
//!     -----------------------
//!     total       3616 bytes
//!
//! NOTE: As of 2026-05-03 the exit-relay-v2 binary does NOT yet load this
//! keyfile (see exit-relay-v2/src/main.rs lines 41-46 — generates ephemeral
//! keys and warns). The keyfile is staged here so that the loader can be
//! activated in a follow-up patch without changing the operational pipeline.

use ladon_relay_core_v2::hash::exit_id_from_hkem_pk;
use ladon_relay_core_v2::hkem::HkemKeyPair;
use pqcrypto_traits::kem::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: gen_host_secrets <output-keyfile-path>");
        std::process::exit(2);
    }
    let out_path = PathBuf::from(&args[1]);

    // 1. HKEM keypair.
    let kp = HkemKeyPair::generate();
    let pk_bytes = kp.public_key_bytes();
    let exit_id = exit_id_from_hkem_pk(&pk_bytes);

    // 2. Serialize keyfile: x25519_sk || kyber768_sk || kyber768_pk.
    let x_sk_bytes = kp.x_sk.to_bytes();
    let ky_sk_bytes = kp.ky_sk.as_bytes();
    let ky_pk_bytes = kp.ky_pk.as_bytes();

    let mut keyfile = Vec::with_capacity(x_sk_bytes.len() + ky_sk_bytes.len() + ky_pk_bytes.len());
    keyfile.extend_from_slice(&x_sk_bytes);
    keyfile.extend_from_slice(ky_sk_bytes);
    keyfile.extend_from_slice(ky_pk_bytes);

    // Defensive sanity-check on lengths (Kyber768 sizes are fixed by the spec).
    if x_sk_bytes.len() != 32 {
        eprintln!("FATAL: unexpected x25519 sk length {}", x_sk_bytes.len());
        std::process::exit(3);
    }
    if ky_pk_bytes.len() != 1184 {
        eprintln!("FATAL: unexpected kyber768 pk length {}", ky_pk_bytes.len());
        std::process::exit(3);
    }

    // 3. Write keyfile mode 0600, fail if exists.
    if out_path.exists() {
        eprintln!("REFUSING TO OVERWRITE existing keyfile: {}", out_path.display());
        std::process::exit(4);
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&out_path)?;
    f.write_all(&keyfile)?;
    f.sync_all()?;
    drop(f);

    // 4. Generate 32-byte S2S HMAC key.
    let mut s2s = [0u8; 32];
    OsRng.fill_bytes(&mut s2s);

    // 5. Emit JSON to stdout (machine-readable for the bash wrapper).
    println!("{{");
    println!("  \"hkem_keyfile\": \"{}\",", out_path.display());
    println!("  \"hkem_keyfile_bytes\": {},", keyfile.len());
    println!("  \"exit_id_hex\": \"{}\",", hex::encode(exit_id.as_bytes()));
    println!("  \"hkem_pk_hex\": \"{}\",", hex::encode(pk_bytes));
    println!("  \"s2s_hmac_key_hex\": \"{}\"", hex::encode(s2s));
    println!("}}");

    Ok(())
}
