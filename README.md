# ys-browser-parser

Yamato Security's maintained fork of Sootmark's [browser](https://github.com/Sootmark/browser),
[sqlite](https://github.com/Sootmark/sqlite) and [plist](https://github.com/Sootmark/plist) crates
(Florian Amette): browser history, downloads, cookies and form entries for forensics, from the
databases read without SQLite, with the deleted entries they still hold. It is the browser parser
of [Juntei](https://github.com/Yamato-Security/juntei). The three upstream histories are kept
(imported into `browser/`, `sqlite/` and `plist/`), and their code stays under its MIT OR Apache-2.0
license (see [Licence](#licence)); each crate's README is upstream's, updated for what the fork
changed.

| Crate | Library | What it reads |
| --- | --- | --- |
| [`ys-browser-parser`](browser/) | `browser` | Chromium (`History`, `Cookies`, `Web Data`, caches, extensions), Firefox (`places.sqlite`, `cookies.sqlite`, caches), Safari, Opera 12, Internet Explorer and legacy Edge (`WebCacheV01.dat`), Java cache index files |
| [`ys-browser-parser-sqlite`](sqlite/) | `sqlite` | SQLite databases without SQLite: header, b-trees, overflow chains, records, the schema, a write-ahead log's committed frames, and deleted records |
| [`ys-browser-parser-plist`](plist/) | `plist` | Apple property lists (binary and XML, NSKeyedArchiver), for Safari |

`WebCacheV01.dat` is read with [ys-srum-parser](https://github.com/Yamato-Security/ys-srum-parser)'s
ESE reader (`ys-srum-parser-ese`), Yamato Security's fork of Sootmark's ese, so the two parsers share
one ESE engine.

## Why these crates

Two Rust libraries read the browser databases Juntei needs: Sootmark's `sootmark-browser` 0.7.0 (on
`sootmark-sqlite` 0.2.0, its own SQLite reader) and SecurityRonin's
[browser-forensic](https://github.com/SecurityRonin/browser-forensic) (`browser-forensic-chrome` and
`-firefox` 0.2.2, commit 986791b, on SQLite through rusqlite). Both were run on the same databases
with four references:

- the `sqlite3` library 3.53.4, querying each table on a copy of the database and its `-wal`;
- [plaso](https://github.com/log2timeline/plaso) 20261027 (`log2timeline --parsers sqlite`);
- [Velociraptor](https://github.com/Velocidex/velociraptor) 0.77.3 with
  [SQLiteHunter](https://github.com/Velocidex/SQLiteHunter)'s definitions (11935e2), their SQL and
  VQL run through Velociraptor's `sqlite()` with the artifact's `SQLITE_ALWAYS_MAKE_TEMPFILE`;
- [Hindsight](https://github.com/obsidianforensics/hindsight) 2026.06, for Chromium.

Each count is the rows a tool gave that equal the `sqlite3` rows (time to the microsecond, URL,
title, path, flags; Velociraptor prints times to the second and Hindsight goes through floats, so
they were compared at that precision). A dash: the tool doesn't read that data.

**plaso's test files** (Apache-2.0, in `browser/tests/fixtures/plaso/`): Chrome 8, 57, 58 and 59
`History`, Chrome 17 and 68 `Cookies`, `Web Data`, Firefox `places.sqlite` (23 and older, 25, 118)
and cookies (Firefox 2 and 10):

| Rows | sootmark-browser | browser-forensic | plaso | Velociraptor | Hindsight |
| --- | --- | --- | --- | --- | --- |
| Chromium visits (73) | **73** | 4: Chrome 8 fails (no `visit_duration`) | 73 | 4 | 73 |
| Chromium downloads (6) | **6** | 4: Chrome 8 fails (no `downloads_url_chains`) | 6 | 0: rows never opened are filtered out | 6 |
| Chromium cookies (565) | **565** | 0: both fail (no `samesite`, no `is_secure`) | 565 | 0 | 5 |
| Chromium form entries (3) | **3** | 3 | 3 | no definition | 0 |
| Firefox visits (124) | **124** | 124 | 124 | 89: the files of Firefox 25 and older fail | – |
| Firefox downloads (8) | **8** | 8 | 7 | 8 | – |
| Firefox cookies (103) | **103** | 13: Firefox 2's file fails (no `sameSite`) | 103 | 103 | – |

**Current browsers**: profiles made by driving Chromium 150 and Firefox 140 (headless, over the
DevTools protocol and WebDriver BiDi) through a local test site: typed visits, a link, a redirect,
cookies, a download and two form submissions. Each profile was copied while the browser ran (the
Firefox databases' latest rows only in their `-wal`), after the browser deleted cookies itself, and
after it closed:

| Rows | sootmark-browser | browser-forensic | plaso | Velociraptor | Hindsight |
| --- | --- | --- | --- | --- | --- |
| Chromium visits, downloads, cookies, form entries (39, 3, 10, 9) | **all** | all | all | all but the 3 downloads (no form entry definition) | all |
| Firefox visits (57) | **57** | 57 | 54, and 2 deleted visits as live | 54, and 2 deleted visits as live | – |
| Firefox downloads (4) | **4** | 4 | 0 | 4 | – |
| Firefox cookies (14) | **14** | 14 | 8: the `-wal` isn't read | 8: the `-wal` isn't read | – |
| Firefox form history (9) | not read | 9 | – | 9 | – |

**Deleted history**: two pages and their visits deleted from the Firefox 140 `places.sqlite` the way
the browsers delete (write-ahead log, `secure_delete` on, no checkpoint):

- sootmark-browser: the 2 visits and the 2 pages, each with its time, URL and (Japanese) title, from
  the database file's copies of the pages the log replaced; and no deleted entry on the other 14
  `History` and `places.sqlite` files.
- browser-forensic: none of them (`recover_from_wal`, `carve_sqlite_free_pages`). Its log recovery
  does find the cookie Firefox deleted, as 2 records of unnamed columns.

**Damaged files**: 198 copies of the 33 databases above, cut short, with bytes flipped, a page
zeroed or filled with noise, or an invalid page size. Neither library panicked or hung;
sootmark-browser still read 77% of them (the rest reported as unreadable), browser-forensic 49%
(rusqlite refuses a damaged file as a whole).

sootmark-browser was taken: every reference row read, of every version, in the write-ahead log
too, deleted history recovered without false positives, no SQLite library to build, and typed
records. browser-forensic does more of Chromium's other files (login data, sessions, shortcuts,
top sites, and opt-in decryption); those are candidates for this fork, with Firefox's form history,
which the fork now reads.

What the fork changes:

| Change | Source |
| --- | --- |
| The crates named after the repository (`ys-browser-parser`, `ys-browser-parser-sqlite`, `ys-browser-parser-plist`; libraries `browser`, `sqlite`, `plist`), version 1.0.0, edition 2024, Rust 1.99 | fork |
| `WebCacheV01.dat` read with ys-srum-parser's ESE reader instead of sootmark-ese | fork |
| Firefox's form history (`formhistory.sqlite`): entries with their GUIDs and sources, available removal tombstones, and deleted entries recovered (`read_form_history`; Chromium's `Web Data` too). See the [interpretation limits](browser/README.md#form-history-interpretation). | fork (#2) |
| Internet Explorer and legacy Edge's `WebCacheV01.dat` read whole (`read_webcache`): the history entries with their page titles and all their times (`ModifiedTime` local in the day and week containers), downloads (URL, saved and partial paths, size, start, referrer, MIME type), cached files, cookie files and the other containers' entries, and the cookies Windows 10 keeps in the database. Checked against dissect.database's reading of plaso's two WebCache databases: every row the same. | fork (#9) |
| One workspace and one CI (Linux, macOS, Windows, MSRV, wasm32, cargo-deny, the license notice), actions pinned by commit | fork |
| Code changed for Rust 1.99's lints (`as_chunks`, `is_multiple_of`, `let` chains) and the 2024 style edition, with the same behaviour (all upstream tests pass) | fork |
| Safari binary-cookie page checksums wrap correctly for large pages instead of panicking | fork |
| SQLite hardening: rejected WAL headers cannot affect the file fallback, damaged values stay NULL, and image exports cannot expand tiny logs into huge allocations | fork |

## Licence

ys-browser-parser is copyright Shirofune Security Co., Ltd. and released under the [Reciprocal
Public License 1.5](LICENSE) (RPL-1.5), whose text is also in `browser/`, `sqlite/` and `plist/`. It
is changed from [Sootmark/browser](https://github.com/Sootmark/browser),
[Sootmark/sqlite](https://github.com/Sootmark/sqlite) and
[Sootmark/plist](https://github.com/Sootmark/plist) (copyright Cyber Experts), whose code stays under
the MIT License or the Apache License 2.0 (`LICENSE-MIT`, `LICENSE-APACHE`): each Rust file changed
from them says so in its header. The test files keep their licences: plaso's (Apache-2.0), with its
licence beside them; the others are made by the scripts beside them.
