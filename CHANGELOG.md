# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's fork, of three crates: sootmark-browser 0.7.0 (Sootmark/browser
b2a6f96), sootmark-sqlite 0.2.0 (Sootmark/sqlite a42d881) and sootmark-plist 0.1.0 (Sootmark/plist
854c8f4). (@YamatoSecurity)

### Added
- Firefox's form history (`formhistory.sqlite`): `read_autofill` reads its entries too, with
  their GUID and sources (`AutofillEntry::guid`, `sources`, and `store`: `FormStore::Chromium` or
  `Firefox`), and `detect` knows it. `read_form_history` reads a form history whole, Chromium's or
  Firefox's: the entries, the deleted entries the database and its log still hold
  (`RecoveredFormEntry`, with their provenance) and Firefox's removals (`FormRemoval`). (#2)
  (@YamatoSecurity)

### Fixed
- When a WAL's committed page 1 is invalid or disagrees with its page size, discard its
  header along with the WAL and retain the readable database file. A valid logged header can
  still restore a damaged file header. (@YamatoSecurity)
- Keep unread values in damaged SQLite rows NULL instead of substituting schema defaults.
  Complete older rows still receive legitimate defaults for columns added later. (@YamatoSecurity)
- Bound SQLite image-export allocations in proportion to the supplied file and WAL pages,
  and report implausible committed sizes. Small gaps retain their original page offsets.
  (@YamatoSecurity)
- Use wrapping arithmetic for Safari binary-cookie page checksums; large pages no longer
  panic when their sum exceeds 32 bits. (@YamatoSecurity)

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
