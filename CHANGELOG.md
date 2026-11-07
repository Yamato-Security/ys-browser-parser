# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's fork, of three crates: sootmark-browser 0.7.0 (Sootmark/browser
b2a6f96), sootmark-sqlite 0.2.0 (Sootmark/sqlite a42d881) and sootmark-plist 0.1.0 (Sootmark/plist
854c8f4). (@YamatoSecurity)

### Changed
- License: ys-browser-parser is copyright Shirofune Security Co., Ltd. and released under the
  Reciprocal Public License 1.5 (RPL-1.5). Upstream's code stays under MIT OR Apache-2.0
  (`LICENSE-MIT`, `LICENSE-APACHE`). Every Rust file carries the copyright and the RPL License
  Notice, and names the upstream crate it is changed from, with its copyright and license.
  (@YamatoSecurity)
- The crates are named after their repository: `ys-browser-parser` (was `sootmark-browser`; library
  `browser`), `ys-browser-parser-sqlite` (was `sootmark-sqlite`; library `sqlite`) and
  `ys-browser-parser-plist` (was `sootmark-plist`; library `plist`), version 1.0.0, by Florian
  Amette and Zach Mathis (@yamatosecurity), on Rust's 2024 edition, and require Rust 1.99. Depend
  on them as `browser = { package = "ys-browser-parser", … }`. (@YamatoSecurity)
- `WebCacheV01.dat` is read with ys-srum-parser's ESE reader (`ys-srum-parser-ese`, Yamato
  Security's fork of sootmark-ese) instead of sootmark-ese. (@YamatoSecurity)
- The three crates are one workspace with one CI: tests on Linux, macOS and Windows, the MSRV, a
  wasm32 build, cargo-deny and the license notice, with actions pinned by commit. (@YamatoSecurity)
