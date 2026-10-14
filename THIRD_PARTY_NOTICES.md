# Third-party notices

LADON messenger is licensed under the GNU Affero General Public License v3.0
(see `LICENSE`). It includes or links the following third-party components.
Their full license texts are in `LICENSES/`.

## Bundled in this repository

| Component | Version | License | Location | License text |
|---|---|---|---|---|
| liboqs (Open Quantum Safe) | 0.15.0 | MIT | `LadonApp/Crypto/liboqs.a`, `LadonApp/Crypto/oqs/` | `LICENSES/liboqs-MIT.txt` |
| BLAKE3 (C implementation) | — | CC0 1.0, or Apache 2.0 | `LadonApp/Crypto/blake3/` | `LICENSES/BLAKE3-CC0.txt` |
| Argon2 reference implementation | — | CC0 1.0, or Apache 2.0 | `Packages/LadonArgon2/Sources/CArgon2/` | `LICENSES/Argon2-CC0-or-Apache-2.0.txt` |
| SQLCipher (Community Edition), with SQLite 3.51.2 | 4.13.0 | BSD 3-Clause (SQLite: public domain) | `LadonApp/Frameworks/SQLCipher.xcframework` | `LICENSES/SQLCipher-BSD-3-Clause.txt` |
| IPtProxy (Guardian Project) | — | MIT | `LadonApp/Frameworks/IPtProxy.xcframework` | `LICENSES/IPtProxy-MIT.txt` |
| — lyrebird (inside IPtProxy) | 0.9.0 | BSD 3-Clause | same | `LICENSES/lyrebird-BSD-3-Clause.txt` |
| — Snowflake (inside IPtProxy) | 2.15.1 | BSD 3-Clause | same | `LICENSES/snowflake-BSD-3-Clause.txt` |
| — goptlib (inside IPtProxy) | — | CC0 1.0 | same | `LICENSES/goptlib-CC0.txt` |
| Manrope (font) | — | SIL Open Font License 1.1 | `LadonApp/Fonts/Manrope-*.ttf` | `LICENSES/Manrope-OFL-1.1.txt` |
| JetBrains Mono (font) | — | SIL Open Font License 1.1 | `LadonApp/Fonts/JetBrainsMono-*.ttf` | `LICENSES/JetBrainsMono-OFL-1.1.txt` |

Versions marked "—" are not recorded in the bundled files.

## Downloaded at build time (not in this repository)

`tor.xcframework` is fetched as described in `LadonApp/Frameworks/TOR_FRAMEWORK.lock`
(Tor 0.4.9.14, built by the iCepa Tor.framework project). It contains:

| Component | Version | License | License text |
|---|---|---|---|
| Tor | 0.4.9.14 | BSD 3-Clause (plus the component licenses listed in the file) | `LICENSES/Tor-BSD-3-Clause.txt` |
| Tor.framework (iCepa) | v409.14.1 | MIT | `LICENSES/Tor.framework-MIT.txt` |
| libevent | 2.1.13 | BSD 3-Clause | `LICENSES/libevent-BSD-3-Clause.txt` |
| OpenSSL | 3.6.5 | Apache 2.0 | `LICENSES/OpenSSL-Apache-2.0.txt` |
| liblzma (XZ Utils) | 5.8.4 | BSD Zero Clause | `LICENSES/xz-liblzma-0BSD.txt` |
| zlib | 1.2.12 | zlib License | `LICENSES/zlib.txt` |

## Rust relay dependencies

The relays (`relay-core-v2`, `entry-relay-v2`, `exit-relay-v2`, `push-relay`,
`blob-relay`) depend on crates from crates.io. Exact versions are pinned in each
crate's `Cargo.lock`; each crate carries its own license.
