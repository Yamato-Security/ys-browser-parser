// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/browser (https://github.com/Sootmark/browser), whose code
// is under the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Internet Explorer and legacy Edge's `WebCacheV01.dat`, an ESE database
//! read with `ys-srum-parser-ese`. Its `Containers` table lists the caches,
//! each keeping one row per entry in `Container_<ContainerId>`:
//!
//! - history (`History`, and `MSHist01…` for each day or week): one row per
//!   page, its `Url` written `Visited: alice@https://…` (or
//!   `:2014051220140513: alice@…` in the period containers); local files
//!   opened in Explorer are there too, as `file:///C:/…` URLs. How a page was
//!   reached isn't recorded; the time is `AccessedTime`, the last visit (a
//!   FILETIME, UTC);
//! - downloads (`iedownload`): one row per download, its URL, paths, size and
//!   start in the binary `ResponseHeaders` (see [`download`]);
//! - the others: cached files (`Content`), cookie files (`Cookies`,
//!   `Cookie:alice@example.com/`), web storage (`DOMStore`), compatibility
//!   lists (`iecompat`), notification images (`wpnidm`) and so on, each row
//!   with its URL, file name, size and times.
//!
//! Since Windows 10, the cookies themselves are in the database too, in
//! `CookieEntryEx_<TableId>` tables: `PartitionsEx` says whose (the user's
//! own, legacy Edge's, an app's) by the directory of each table.

use std::collections::HashMap;

use common::time::Ts;
use ese::{Database, Row, Table, Value};

use crate::{Download, Transition, Visit};

const CONTAINERS: &str = "Containers";
const PARTITIONS_EX: &str = "PartitionsEx";
const COOKIE_TABLES: &str = "cookieentryex_";

/// Containers without an entry table of their own, as plaso notes too.
const TABLELESS: [&str; 3] = [
    "MicrosoftEdge_DNTException",
    "MicrosoftEdge_EmieSiteList",
    "MicrosoftEdge_EmieUserList",
];

/// A WebCache database read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCache {
    /// The caches its `Containers` table lists, in its order.
    pub containers: Vec<WebCacheContainer>,
    /// The entries of its history containers, container by container: each
    /// a visit (as [`read`](crate::read) gives them) with the entry's other
    /// times.
    pub visits: Vec<WebCacheVisit>,
    /// The downloads of its `iedownload` containers.
    pub downloads: Vec<WebCacheDownload>,
    /// The entries of every other container (cached files, cookie files, web
    /// storage, compatibility lists, …), container by container.
    pub entries: Vec<WebCacheEntry>,
    /// The cookies of its `CookieEntryEx` tables (Windows 10 and later).
    pub cookies: Vec<WebCacheCookie>,
    /// Damage in the database, and rows that couldn't be read.
    pub problems: Vec<String>,
}

/// An entry of a history container (`History`, `MSHist01…`): a URL visited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCacheVisit {
    /// The visit, as [`read`](crate::read) gives it: its `id` the entry's
    /// `EntryId`, its `table` its container's table, its `time`
    /// `AccessedTime` (the last visit), its `visit_count` `AccessCount`, its
    /// `user` the account of the URL (`Visited: alice@…`).
    pub visit: Visit,
    /// Its container's `ContainerId`.
    pub container: i64,
    /// `CreationTime`.
    pub created: Option<Ts>,
    /// `ModifiedTime`. In a day's or a week's container (`MSHist01…`) it is
    /// a local time, the wall clock of the system's time zone
    /// ([`Semantic::LocalUnknownZone`](common::time::Semantic::LocalUnknownZone));
    /// in `History`, UTC.
    pub modified: Option<Ts>,
    /// `ExpiryTime`: when the entry leaves the history.
    pub expires: Option<Ts>,
    /// `SyncTime`.
    pub synced: Option<Ts>,
    /// `SyncCount`.
    pub sync_count: Option<i64>,
    /// `Type`, as stored.
    pub entry_type: Option<i64>,
    /// `Flags`, as stored.
    pub flags: Option<i64>,
}

/// A cache: a row of the `Containers` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCacheContainer {
    /// `ContainerId`: its entries are in `Container_<id>`.
    pub id: i64,
    /// `Name`: `Content`, `History`, `MSHist01…`, `Cookies`, `iedownload`,
    /// `DOMStore`, `iecompat`, ….
    pub name: String,
    /// `Directory`: where its files are on the disk.
    pub directory: Option<String>,
    /// `PartitionId`: `M` for the user's own caches, an app container's SID
    /// for an app's.
    pub partition: Option<String>,
    /// `SecureDirectories`: the subfolders its files are in, 8 characters
    /// each; an entry's `SecureDirectory` names one, counting from 1.
    pub secure_directories: Vec<String>,
    /// `LastAccessTime`.
    pub last_access: Option<Ts>,
    /// `LastScavengeTime`: when it was last cleaned up.
    pub last_scavenge: Option<Ts>,
}

/// An entry of a container other than history and downloads: a cached file
/// (`Content`), a cookie file (`Cookies`), web storage (`DOMStore`), a
/// compatibility list entry (`iecompat`), ….
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCacheEntry {
    /// Its container's `ContainerId`.
    pub container: i64,
    /// Its container's name.
    pub container_name: String,
    /// `EntryId`, unique within its container.
    pub id: i64,
    /// `Url` as stored: a URL for a cached file, `Cookie:alice@example.com/`
    /// for a cookie file, `DOMStore:https://…`, `iecompat:example.com`, ….
    pub url: String,
    /// The account of a `Cookie:alice@…` URL.
    pub user: Option<String>,
    /// `Filename`: the file in the container's directory (`widgets[1].js`).
    pub file_name: Option<String>,
    /// Where the file is: the container's directory, the secure directory
    /// the entry names, and its file name; none when the entry names a
    /// secure directory the container doesn't list.
    pub file_path: Option<String>,
    /// `FileSize`.
    pub file_size: Option<i64>,
    /// `Type`, as stored.
    pub entry_type: Option<i64>,
    /// `Flags`, as stored.
    pub flags: Option<i64>,
    /// `AccessCount`.
    pub access_count: Option<i64>,
    /// `CreationTime`: when the entry was made.
    pub created: Option<Ts>,
    /// `ModifiedTime`: the resource's last modification, as the server said.
    pub modified: Option<Ts>,
    /// `AccessedTime`: when it was last used.
    pub accessed: Option<Ts>,
    /// `ExpiryTime`.
    pub expires: Option<Ts>,
    /// `SyncTime`: when it was last checked with the server.
    pub synced: Option<Ts>,
    /// `SyncCount`.
    pub sync_count: Option<i64>,
    /// `RequestHeaders`, when text.
    pub request_headers: Option<String>,
    /// `ResponseHeaders`, when HTTP headers (`HTTP/1.1 200 OK…`).
    pub response_headers: Option<String>,
    /// `RedirectUrl`.
    pub redirect_url: Option<String>,
}

/// A download of an `iedownload` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCacheDownload {
    /// The download: its `id` the entry's `EntryId`; its URL, where the file
    /// was saved, where it was written while downloading (`current_path`), its
    /// size (`total_bytes`), start, referring page and MIME type, as its
    /// record has them; the rest none.
    pub download: Download,
    /// Its container's `ContainerId`.
    pub container: i64,
    /// A publisher's name legacy Edge recorded with some downloads (the
    /// signer of the files seen).
    pub publisher: Option<String>,
    /// `AccessedTime`.
    pub accessed: Option<Ts>,
}

/// A cookie of a `CookieEntryEx` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebCacheCookie {
    /// The table: `CookieEntryEx_<TableId>`.
    pub table: String,
    /// The table's directory in `PartitionsEx`: whose cookies they are
    /// (`…\INetCookies\ESE\`, legacy Edge's `…\MicrosoftEdge\Cookies\ESE\`,
    /// an app's).
    pub directory: Option<String>,
    /// `EntryId`, unique within its table.
    pub id: i64,
    /// The host it's for: `RDomain` (`com.example.www`) turned around
    /// (`www.example.com`).
    pub host: String,
    /// `Path`.
    pub path: String,
    /// `Name`.
    pub name: String,
    /// `Value`, as stored.
    pub value: String,
    /// `Expires`.
    pub expires: Option<Ts>,
    /// `LastModified`: when it was set.
    pub modified: Option<Ts>,
    /// `Flags`, as stored.
    pub flags: Option<i64>,
}

/// Whether the file is a WebCache database: an ESE one with `Containers`.
pub(crate) fn is_webcache(db: &Database<'_>) -> bool {
    db.table(CONTAINERS).is_some()
}

/// Every container's entries, and the cookies.
pub(crate) fn read(db: &Database<'_>, mut problems: Vec<String>) -> WebCache {
    let containers = containers(db, &mut problems);
    let mut visits = Vec::new();
    let mut downloads = Vec::new();
    let mut entries = Vec::new();
    for container in &containers {
        let name = format!("Container_{}", container.id);
        let (Some(table), Ok(mut rows)) = (db.table(&name), db.rows(&name)) else {
            if !TABLELESS.contains(&container.name.as_str()) {
                problems.push(format!("{CONTAINERS}: no table {name}"));
            }
            continue;
        };
        if is_history(&container.name) {
            visits.extend(
                rows.by_ref()
                    .filter_map(|row| visit(container, table, &row)),
            );
        } else if container.name == "iedownload" {
            for row in rows.by_ref() {
                downloads.push(download(container, table, &row, &mut problems));
            }
        } else {
            entries.extend(rows.by_ref().map(|row| entry(container, table, &row)));
        }
        problems.extend(rows.problems().iter().map(|p| format!("{name}: {p}")));
    }
    let cookies = cookies(db, &mut problems);
    WebCache {
        containers,
        visits,
        downloads,
        entries,
        cookies,
        problems,
    }
}

fn is_history(name: &str) -> bool {
    name == "History" || name.starts_with("MSHist")
}

/// The rows of `Containers`.
fn containers(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<WebCacheContainer> {
    let (Some(table), Ok(mut rows)) = (db.table(CONTAINERS), db.rows(CONTAINERS)) else {
        return Vec::new();
    };
    let containers = rows
        .by_ref()
        .filter_map(|row| {
            let get = |name: &str| row.get(table, name);
            Some(WebCacheContainer {
                id: get("ContainerId").and_then(Value::as_i64)?,
                name: text(get("Name"))?,
                directory: text(get("Directory")),
                partition: text(get("PartitionId")),
                secure_directories: text(get("SecureDirectories"))
                    .map(|names| secure_directories(&names))
                    .unwrap_or_default(),
                last_access: filetime(get("LastAccessTime")),
                last_scavenge: filetime(get("LastScavengeTime")),
            })
        })
        .collect();
    problems.extend(rows.problems().iter().map(|p| format!("{CONTAINERS}: {p}")));
    containers
}

/// `SecureDirectories`, 8 characters a name.
fn secure_directories(names: &str) -> Vec<String> {
    let chars: Vec<char> = names.chars().collect();
    chars
        .chunks(8)
        .map(|name| name.iter().collect::<String>())
        .collect()
}

fn visit(container: &WebCacheContainer, table: &Table, row: &Row) -> Option<WebCacheVisit> {
    let get = |name: &str| row.get(table, name);
    let integer = |name: &str| get(name).and_then(Value::as_i64);
    let (user, url) = split_url(get("Url").and_then(Value::as_text)?);
    let time = integer("AccessedTime")
        .and_then(|ticks| u64::try_from(ticks).ok())
        .map(Ts::from_filetime);
    let modified = filetime(get("ModifiedTime"));
    let visit = Visit {
        id: integer("EntryId").unwrap_or_default(),
        table: table.name.clone(),
        time,
        url: url.to_owned(),
        title: String::new(),
        user: user.map(str::to_owned),
        transition: Transition::NotRecorded,
        from_visit: None,
        duration: None,
        visit_count: integer("AccessCount"),
        typed: false,
        typed_count: None,
        hidden: false,
        frecency: None,
    };
    Some(WebCacheVisit {
        visit,
        container: container.id,
        created: filetime(get("CreationTime")),
        modified: if container.name.starts_with("MSHist") {
            modified.and_then(local)
        } else {
            modified
        },
        expires: filetime(get("ExpiryTime")),
        synced: filetime(get("SyncTime")),
        sync_count: integer("SyncCount"),
        entry_type: integer("Type"),
        flags: integer("Flags"),
    })
}

/// A time read as UTC that is the wall clock of an unknown zone.
fn local(time: Ts) -> Option<Ts> {
    Some(Ts::from_local_ticks(time.ticks()?, time.precision()))
}

fn entry(container: &WebCacheContainer, table: &Table, row: &Row) -> WebCacheEntry {
    let get = |name: &str| row.get(table, name);
    let integer = |name: &str| get(name).and_then(Value::as_i64);
    let url = text(get("Url")).unwrap_or_default();
    let user = url
        .strip_prefix("Cookie:")
        .and_then(|rest| rest.split_once('@'))
        .map(|(user, _)| user.to_owned())
        .filter(|user| !user.is_empty() && !user.contains('/'));
    let file_name = text(get("Filename"));
    let file_path = file_name
        .as_deref()
        .and_then(|name| file_path(container, integer("SecureDirectory"), name));
    WebCacheEntry {
        container: container.id,
        container_name: container.name.clone(),
        id: integer("EntryId").unwrap_or_default(),
        url,
        user,
        file_name,
        file_path,
        file_size: integer("FileSize"),
        entry_type: integer("Type"),
        flags: integer("Flags"),
        access_count: integer("AccessCount"),
        created: filetime(get("CreationTime")),
        modified: filetime(get("ModifiedTime")),
        accessed: filetime(get("AccessedTime")),
        expires: filetime(get("ExpiryTime")),
        synced: filetime(get("SyncTime")),
        sync_count: integer("SyncCount"),
        request_headers: get("RequestHeaders")
            .and_then(Value::as_bytes)
            .and_then(headers),
        response_headers: get("ResponseHeaders")
            .and_then(Value::as_bytes)
            .filter(|bytes| bytes.starts_with(b"HTTP/"))
            .and_then(headers),
        redirect_url: text(get("RedirectUrl")),
    }
}

/// The container's directory, the secure directory the entry names (from
/// 1; none named: the directory itself) and the file name.
fn file_path(container: &WebCacheContainer, secure: Option<i64>, name: &str) -> Option<String> {
    let directory = container.directory.as_deref()?.trim_end_matches('\\');
    match secure {
        None | Some(0) => Some(format!("{directory}\\{name}")),
        Some(index) => {
            let folder = container
                .secure_directories
                .get(usize::try_from(index).ok()?.checked_sub(1)?)?;
            Some(format!("{directory}\\{folder}\\{name}"))
        }
    }
}

/// Headers as text: UTF-8, no control characters but line ends and tabs,
/// trailing NULs dropped.
fn headers(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |at| at + 1);
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    (!text.is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\r' | '\n' | '\t')))
    .then(|| text.to_owned())
}

/// Bytes of an `iedownload` record's header that hold its numbers: its size
/// is the record's first `u32` (0x89 and 0x8C seen).
const DOWNLOAD_HEADER_MIN: usize = 0x50;
/// The download's start, a FILETIME.
const DOWNLOAD_START: usize = 0x24;
/// The file's size, a `u64`.
const DOWNLOAD_SIZE: usize = 0x48;

/// A download: its `ResponseHeaders` read. The layout isn't documented;
/// what this reads was the same in every record seen (Internet Explorer 11
/// on Windows 8.1 and 10, legacy Edge): a header whose size the first `u32`
/// gives, the start (a FILETIME at 0x24, the entry's `AccessedTime` to the
/// millisecond) and size (a `u64` at 0x48), and at the end UTF-16 strings,
/// each ending in a NUL. The last ones are, from the end, where the file was
/// saved, its URL and where it was written while downloading (a `.partial`
/// file, or the cache's copy); before them, the MIME type, the referring
/// page and, with legacy Edge, a publisher.
fn download(
    container: &WebCacheContainer,
    table: &Table,
    row: &Row,
    problems: &mut Vec<String>,
) -> WebCacheDownload {
    let get = |name: &str| row.get(table, name);
    let id = get("EntryId").and_then(Value::as_i64).unwrap_or_default();
    let accessed = filetime(get("AccessedTime"));
    let record = get("ResponseHeaders")
        .and_then(Value::as_bytes)
        .unwrap_or_default();
    let header = u32_at(record, 0).map_or(0, |size| size as usize);
    let valid_header = (DOWNLOAD_HEADER_MIN..=record.len()).contains(&header);
    let start = valid_header
        .then(|| u64_at(record, DOWNLOAD_START))
        .flatten()
        .filter(|&ticks| ticks != 0)
        .map(Ts::from_filetime)
        .or(accessed);
    let size = valid_header
        .then(|| u64_at(record, DOWNLOAD_SIZE))
        .flatten()
        .and_then(|size| i64::try_from(size).ok());
    // The strings are aligned on the record's end, not its header's (0x89).
    // A corrupt length must not turn bytes of another layout into a size,
    // timestamp or string section. Keep the entry's own URL/access time instead.
    let tail = record
        .get(header..)
        .filter(|_| valid_header)
        .unwrap_or_default();
    let mut strings = trailing_strings(&tail[tail.len() % 2..]);
    let mut download = Download {
        id,
        url: String::new(),
        url_chain: Vec::new(),
        target_path: String::new(),
        current_path: None,
        start,
        end: None,
        received_bytes: None,
        total_bytes: size,
        state: None,
        danger_type: None,
        interrupt_reason: None,
        referrer: None,
        tab_url: None,
        mime_type: None,
        opened: None,
        deleted: None,
    };
    let mut publisher = None;
    let valid_strings = strings.len() >= 2
        && is_path(&strings[strings.len() - 1])
        && is_uri(&strings[strings.len() - 2]);
    if !valid_header {
        problems.push(format!(
            "{}: download {id}: invalid header size {header} for {} bytes",
            table.name,
            record.len()
        ));
        download.url = text(get("Url")).unwrap_or_default();
    } else if !valid_strings {
        problems.push(format!(
            "{}: download {id}: no valid URL and Windows path in its record",
            table.name
        ));
        download.url = text(get("Url")).unwrap_or_default();
    } else {
        download.target_path = strings.pop().unwrap_or_default();
        download.url = strings.pop().unwrap_or_default();
        if strings.last().is_some_and(|s| is_path(s)) {
            download.current_path = strings.pop();
        }
        for string in strings.into_iter().rev() {
            if is_mime_type(&string) {
                download.mime_type.get_or_insert(string);
            } else if string.contains("://") {
                download.referrer.get_or_insert(string);
            } else {
                publisher.get_or_insert(string);
            }
        }
    }
    WebCacheDownload {
        download,
        container: container.id,
        publisher,
        accessed,
    }
}

/// The NUL-terminated UTF-16 strings that end `data`, in order: as many as
/// are text, counting back from its end.
fn trailing_strings(data: &[u8]) -> Vec<String> {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let Some((&0, mut rest)) = units.split_last() else {
        return Vec::new();
    };
    let mut strings = Vec::new();
    loop {
        let start = rest
            .iter()
            .rposition(|&unit| unit == 0)
            .map_or(0, |at| at + 1);
        let Ok(string) = String::from_utf16(&rest[start..]) else {
            break;
        };
        if string.is_empty() || string.chars().any(char::is_control) {
            break;
        }
        strings.push(string);
        if start == 0 {
            break;
        }
        rest = &rest[..start - 1];
    }
    strings.reverse();
    strings
}

fn is_path(string: &str) -> bool {
    let bytes = string.as_bytes();
    string.starts_with("\\\\")
        || string.starts_with("//")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

/// An absolute URI, including `file:`, `data:` and `blob:` downloads.
fn is_uri(string: &str) -> bool {
    string.split_once(':').is_some_and(|(scheme, rest)| {
        !rest.is_empty()
            && !is_path(string)
            && scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    })
}

/// `type/subtype`: letters, digits and `+.-` only.
fn is_mime_type(string: &str) -> bool {
    string.split_once('/').is_some_and(|(kind, subtype)| {
        let token = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+.-_".contains(&b))
        };
        token(kind) && token(subtype)
    })
}

/// The `CookieEntryEx` tables' cookies, table by table.
fn cookies(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<WebCacheCookie> {
    let directories = cookie_directories(db, problems);
    let mut cookies = Vec::new();
    for table in db
        .tables
        .iter()
        .filter(|table| table.name.to_ascii_lowercase().starts_with(COOKIE_TABLES))
    {
        let Ok(mut rows) = db.rows(&table.name) else {
            continue;
        };
        let directory = table.name[COOKIE_TABLES.len()..]
            .parse::<i64>()
            .ok()
            .and_then(|id| directories.get(&id).cloned());
        cookies.extend(rows.by_ref().map(|row| {
            let get = |name: &str| row.get(table, name);
            WebCacheCookie {
                table: table.name.clone(),
                directory: directory.clone(),
                id: get("EntryId").and_then(Value::as_i64).unwrap_or_default(),
                host: text(get("RDomain"))
                    .map(|domain| domain.split('.').rev().collect::<Vec<_>>().join("."))
                    .unwrap_or_default(),
                path: text(get("Path")).unwrap_or_default(),
                name: cookie_text(get("Name")),
                value: cookie_text(get("Value")),
                expires: filetime(get("Expires")),
                modified: filetime(get("LastModified")),
                flags: get("Flags").and_then(Value::as_i64),
            }
        }));
        problems.extend(
            rows.problems()
                .iter()
                .map(|p| format!("{}: {p}", table.name)),
        );
    }
    cookies
}

/// `PartitionsEx`: each table's directory, by its `TableId`.
fn cookie_directories(db: &Database<'_>, problems: &mut Vec<String>) -> HashMap<i64, String> {
    let (Some(table), Ok(mut rows)) = (db.table(PARTITIONS_EX), db.rows(PARTITIONS_EX)) else {
        return HashMap::new();
    };
    let directories = rows
        .by_ref()
        .filter_map(|row| {
            let id = row.get(table, "TableId").and_then(Value::as_i64)?;
            Some((id, text(row.get(table, "Directory"))?))
        })
        .collect();
    problems.extend(
        rows.problems()
            .iter()
            .map(|p| format!("{PARTITIONS_EX}: {p}")),
    );
    directories
}

/// A cookie's name or value: bytes ending in a NUL, as text.
fn cookie_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Binary(bytes)) => {
            let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |at| at + 1);
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }
        Some(Value::Text(text)) => text.trim_end_matches('\0').to_owned(),
        _ => String::new(),
    }
}

/// Text, none when empty.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_text)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A FILETIME column: none when zero or negative.
fn filetime(value: Option<&Value>) -> Option<Ts> {
    value
        .and_then(Value::as_i64)
        .and_then(|ticks| u64::try_from(ticks).ok())
        .filter(|&ticks| ticks != 0)
        .map(Ts::from_filetime)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// `Visited: alice@https://x` as the account and the URL; a URL without
/// the prefix as it is.
fn split_url(raw: &str) -> (Option<&str>, &str) {
    let Some((head, url)) = raw.split_once('@') else {
        return (None, raw);
    };
    // The prefix is `Visited: ` or `:<period>: `, never part of a URL.
    match head.rsplit_once(": ") {
        Some((prefix, user)) if !prefix.contains('/') && !user.contains('/') => (Some(user), url),
        _ => (None, raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(strings: &[&str]) -> Vec<u8> {
        strings
            .iter()
            .flat_map(|s| s.encode_utf16().chain([0]))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A real entry's schema with an independently constructed download blob.
    fn read_download(record: Vec<u8>) -> (WebCacheDownload, Vec<String>) {
        use std::io::Read;
        let mut data = Vec::new();
        common::gzip::Decoder::new(
            &include_bytes!("../tests/fixtures/plaso/WebCacheV01.dat.gz")[..],
        )
        .read_to_end(&mut data)
        .unwrap();
        let db = Database::open(&data).unwrap();
        let mut problems = Vec::new();
        let container = containers(&db, &mut problems)
            .into_iter()
            .find(|c| c.name == "iedownload")
            .unwrap();
        let table = db.table(&format!("Container_{}", container.id)).unwrap();
        let mut row = db.rows(&table.name).unwrap().next().unwrap();
        row.values[table.column_index("ResponseHeaders").unwrap()] = Value::Binary(record);
        row.values[table.column_index("Url").unwrap()] =
            Value::Text("https://example.com/fallback.exe".into());
        problems.clear();
        (download(&container, table, &row, &mut problems), problems)
    }

    fn download_blob(strings: &[&str]) -> Vec<u8> {
        let mut record = vec![0; 0x8c];
        record[..4].copy_from_slice(&0x8cu32.to_le_bytes());
        record[DOWNLOAD_START..DOWNLOAD_START + 8]
            .copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        record[DOWNLOAD_SIZE..DOWNLOAD_SIZE + 8].copy_from_slice(&1234u64.to_le_bytes());
        record.extend(utf16(strings));
        record
    }

    #[test]
    fn download_header_must_fit_the_record() {
        for size in [0, (DOWNLOAD_HEADER_MIN - 1) as u32, u32::MAX] {
            let mut record = download_blob(&["https://example.com/a.exe", "C:\\a.exe"]);
            record[..4].copy_from_slice(&size.to_le_bytes());
            let (found, problems) = read_download(record);
            assert_eq!(found.download.total_bytes, None, "header size {size}");
            assert_eq!(found.download.start, found.accessed);
            assert_eq!(found.download.url, "https://example.com/fallback.exe");
            assert_eq!(found.download.target_path, "");
            assert!(
                problems.iter().any(|p| p.contains("header")),
                "{problems:?}"
            );
        }
    }

    #[test]
    fn download_strings_must_identify_a_url_and_windows_path() {
        for (url, path) in [
            ("not a URL", "C:\\a.exe"),
            ("https://example.com/a.exe", "not a path"),
            ("not a URL", "not a path"),
        ] {
            let (found, problems) = read_download(download_blob(&[url, path]));
            assert_eq!(found.download.url, "https://example.com/fallback.exe");
            assert_eq!(found.download.target_path, "");
            assert_eq!(problems.len(), 1);
        }
    }

    #[test]
    fn valid_download_uris_and_unicode_paths_remain_readable() {
        for url in [
            "https://example.com/a.exe",
            "file:///C:/source/a.exe",
            "data:application/octet-stream;base64,QQ==",
            "blob:https://example.com/download-id",
        ] {
            for path in [
                r"C:\Users\田中\a.exe",
                "C:/Downloads/a.exe",
                r"\\server\share\a.exe",
            ] {
                let (found, problems) = read_download(download_blob(&[url, path]));
                assert_eq!(found.download.url, url);
                assert_eq!(found.download.target_path, path);
                assert_eq!(found.download.total_bytes, Some(1234));
                assert!(problems.is_empty(), "{problems:?}");
            }
        }
    }

    #[test]
    fn strings_at_the_end_of_a_record() {
        let mut record = vec![0x01, 0x00, 0x7f, 0x00, 0x00, 0x00];
        record.extend(utf16(&["text/plain", "C:\\x.txt"]));
        assert_eq!(trailing_strings(&record), ["text/plain", "C:\\x.txt"]);
        // a string of control characters ends the run
        let mut record = utf16(&["\u{1}\u{2}", "https://a/", "C:\\b"]);
        assert_eq!(trailing_strings(&record), ["https://a/", "C:\\b"]);
        // no final NUL: nothing
        record.truncate(record.len() - 2);
        let none = trailing_strings(&record);
        assert!(none.is_empty(), "{none:?}");
        let none = trailing_strings(&[]);
        assert!(none.is_empty(), "{none:?}");
        // unpaired surrogates aren't text
        let mut record: Vec<u8> = [0xd800u16, 0]
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        record.extend(utf16(&["C:\\b"]));
        assert_eq!(trailing_strings(&record), ["C:\\b"]);
    }

    #[test]
    fn mime_types_and_paths() {
        assert!(is_mime_type("application/pdf"));
        assert!(is_mime_type("application/vnd.ms-excel"));
        assert!(!is_mime_type("https://a/b"));
        assert!(!is_mime_type("Notepad++"));
        assert!(!is_mime_type("a/b/c"));
        assert!(is_path("C:\\Users\\x"));
        assert!(is_path("\\\\server\\share\\x"));
        assert!(!is_path("https://a/"));
        assert!(!is_path("C:"));
    }

    #[test]
    fn files_in_their_secure_directories() {
        let container = WebCacheContainer {
            id: 1,
            name: "Content".into(),
            directory: Some("C:\\Cache\\IE\\".into()),
            partition: None,
            secure_directories: secure_directories("AAAAAAAABBBBBBBB"),
            last_access: None,
            last_scavenge: None,
        };
        assert_eq!(container.secure_directories, ["AAAAAAAA", "BBBBBBBB"]);
        assert_eq!(
            file_path(&container, Some(2), "x[1].js").as_deref(),
            Some("C:\\Cache\\IE\\BBBBBBBB\\x[1].js")
        );
        assert_eq!(
            file_path(&container, None, "y.txt").as_deref(),
            Some("C:\\Cache\\IE\\y.txt")
        );
        assert_eq!(file_path(&container, Some(3), "z"), None);
        assert_eq!(file_path(&container, Some(-1), "z"), None);
    }

    #[test]
    fn headers_as_text() {
        assert_eq!(
            headers(b"HTTP/1.1 200 OK\r\nA: b\r\n\0\0").as_deref(),
            Some("HTTP/1.1 200 OK\r\nA: b\r\n")
        );
        assert_eq!(headers(b"\x01\x02"), None);
        assert_eq!(headers(b"\xff\xfe"), None);
        assert_eq!(headers(b"\0"), None);
    }

    #[test]
    fn urls_with_their_accounts() {
        assert_eq!(
            split_url("Visited: test@https://www.bing.com/search?q=a@b"),
            (Some("test"), "https://www.bing.com/search?q=a@b")
        );
        assert_eq!(
            split_url(":2014051220140513: test@file:///C:/Users/test/x.txt"),
            (Some("test"), "file:///C:/Users/test/x.txt")
        );
        assert_eq!(
            split_url("https://user@example.com/"),
            (None, "https://user@example.com/")
        );
        assert_eq!(split_url("about:blank"), (None, "about:blank"));
        // Windows account names may hold spaces.
        assert_eq!(
            split_url("Visited: John Doe@https://www.bing.com/"),
            (Some("John Doe"), "https://www.bing.com/")
        );
    }
}
