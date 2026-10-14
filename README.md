# LADON messenger

An end-to-end encrypted messenger for iPhone, together with the relay servers it
talks to. This repository contains the complete source of the iOS app and of the
five relay services.

## What is in this repository

| Path | What it is |
|---|---|
| `LadonApp/`, `LadonApp.xcodeproj` | The iOS app (Swift, SwiftUI) |
| `Packages/LadonArgon2` | Argon2id (reference C implementation) as a local Swift package |
| `relay-core-v2/` | Shared Rust library: wire format, cryptography, stores |
| `entry-relay-v2/` | Entry relay — the only server the app connects to |
| `exit-relay-v2/` | Exit relay — mailboxes and the recipient directory |
| `push-relay/` | Push relay — sends the same fixed notification for every message through Apple (`push-relay/src/apns.rs:119`) |
| `blob-relay/` | Blob relay — stores encrypted attachments |
| `formal/` | ProVerif and Tamarin models of the pairing bootstrap and the ratchet |

## How it works, in short

Every statement below points to the code that implements it.

- **Hybrid post-quantum keys.** Each identity has a hybrid signature key
  (Ed25519 + ML-DSA-65) and a hybrid key-encapsulation key (X25519 + ML-KEM-768)
  — `LadonApp/Crypto/V2/BundleV2.swift:8-9`, `LadonApp/Crypto/OQSWrapper.m:14`,
  `:23`, `relay-core-v2/src/hsig.rs:57`.
- **Ratchet with a fresh post-quantum exchange on every turn.** Each DH turn of
  the double ratchet also performs a fresh one-time ML-KEM-768 exchange (frame
  version `0x04`) — `LadonApp/Services/V2/RelayClientV2.swift:110`, `:330-332`.
- **Tor only.** The app sends traffic through its embedded Tor client. A release
  build refuses to create a network session without Tor — there is no clearnet
  fallback (`LadonApp/Services/V2/V2SessionManager.swift:555-580`; the direct
  connection exists only in debug builds).
  One exception the user starts: the optional tip screen
  (`LadonApp/Views/SupportView.swift`) asks Apple's App Store for the tip
  amounts only after a tap on "Show amounts"; StoreKit reaches Apple
  directly, not through Tor, and the screen says so first.
- **Fixed-size requests.** Requests travel in fixed-size sealed frames:
  16,384 bytes on the send lane and 8,192 bytes on the fetch lane
  (`LadonApp/Crypto/V2/SealedRequestV2.swift:89-101`); the relays use the same
  16,384-byte envelope size (`relay-core-v2/src/constants.rs:10`).
- **Pinned servers.** The app connects only to relay servers whose keys are
  compiled into it, one active and one offline reserve key per host
  (`LadonApp/Security/CertificatePinning.swift`,
  `LadonApp/Attachments/BlobRelayPinning.swift`).
- **Keys sealed with the Secure Enclave.** The identity, ratchet sessions,
  one-time prekeys, delivery keys and contacts are stored in the iOS Keychain
  only as ciphertext, sealed with a hybrid key held in Apple's Secure Enclave
  (P-256 + ML-KEM-768) — `LadonApp/Crypto/V2/SealedKeychainV2.swift`. A
  Keychain dump alone does not reveal them; code running on the unlocked
  device can still use the chip.
- **No phone number, no address book.** The identity is a key pair generated on
  the device (`LadonApp/Views/ContentView.swift:1117`); no phone number or e-mail
  is asked for. The app does not use the `Contacts` framework, and
  `LadonApp/Info.plist` has no contacts usage description.

## Formal models

`formal/proverif/bootstrap.pv` models the pairing code and the one-time-prekey
session bootstrap, `formal/proverif/ratchet.pv` the hybrid ratchet (frame
`0x04`), and `formal/tamarin/onetime.spthy` the property that one pairing code
opens at most one session. Each directory has a `run.sh`. The models describe
their own scope and simplifications in their header comments. The pairing-code
model predates the signed pairing-code format now used by
`LadonApp/Services/V2/PairingCodeV4.swift`.

There has been no external security audit.

## Building

**iOS app** — Xcode with the iOS 27 SDK, deployment target iOS 26.0 (the Secure Enclave offers ML-KEM from iOS 26 on). Builds for
devices only: `LadonApp/Crypto/liboqs.a` has no simulator slice
(`SUPPORTED_PLATFORMS = iphoneos`). Before the first build, download and verify
`tor.xcframework` as described in `LadonApp/Frameworks/TOR_FRAMEWORK.lock`.
Open `LadonApp.xcodeproj`, select the `Ladon` scheme and your own signing team.

**Relays** — Rust (edition 2021) and CMake (needed by the vendored liboqs in the
`oqs` crate). In each relay directory:

```bash
cargo build --release
cargo test
```

## License

GNU Affero General Public License v3.0 — see `LICENSE`. Third-party components
and their licenses are listed in `THIRD_PARTY_NOTICES.md`.

## Contributions

External code contributions are not accepted at the moment. Bug reports and
security reports are welcome: info@ladon.app
