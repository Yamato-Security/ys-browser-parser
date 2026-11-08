// Copyright (C) 2026 Shirofune Security Co., Ltd.
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

//! plaso's WebCache databases read whole (`read_webcache`): every container, visit, download,
//! entry and cookie against dissect.database's reading of the same rows
//! (`tests/oracle/webcache.tsv.gz`, see `webcache_tsv.py` beside it), and examples of each.

mod support;

use std::io::Read;

use browser::{Kind, WebCache, read, read_webcache};
use common::time::Ts;

const FILES: [&str; 2] = ["WebCacheV01.dat.gz", "PartitionsEx-WebCacheV01.dat.gz"];

fn webcache(name: &str) -> WebCache {
    read_webcache(&support::fixture(&format!("plaso/{name}"))).unwrap()
}

/// As `webcache_tsv.py` writes text.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn time(value: Option<Ts>) -> String {
    value.and_then(|t| t.to_iso8601()).unwrap_or_default()
}

fn opt<T: ToString>(value: Option<T>) -> String {
    value.map(|v| escape(&v.to_string())).unwrap_or_default()
}

/// Every row of `cache`, one line each as `webcache_tsv.py` writes them.
fn lines(file: &str, cache: &WebCache) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = |values: Vec<String>| {
        lines.push(
            std::iter::once(file.to_owned())
                .chain(values)
                .collect::<Vec<_>>()
                .join("\t"),
        );
    };
    for c in &cache.containers {
        line(vec![
            "container".into(),
            c.id.to_string(),
            escape(&c.name),
            opt(c.directory.as_deref()),
            c.secure_directories.join("|"),
            time(c.last_access),
            time(c.last_scavenge),
        ]);
    }
    for v in &cache.visits {
        line(vec![
            "visit".into(),
            v.table.clone(),
            v.id.to_string(),
            opt(v.user.as_deref()),
            escape(&v.url),
            time(v.time),
        ]);
    }
    for d in &cache.downloads {
        let x = &d.download;
        line(vec![
            "download".into(),
            d.container.to_string(),
            x.id.to_string(),
            escape(&x.url),
            escape(&x.target_path),
            opt(x.current_path.as_deref()),
            time(x.start),
            opt(x.total_bytes),
            opt(x.referrer.as_deref()),
            opt(x.mime_type.as_deref()),
            opt(d.publisher.as_deref()),
            time(d.accessed),
        ]);
    }
    for e in &cache.entries {
        let response = e.response_headers.as_deref();
        line(vec![
            "entry".into(),
            e.container.to_string(),
            escape(&e.container_name),
            e.id.to_string(),
            escape(&e.url),
            opt(e.user.as_deref()),
            opt(e.file_name.as_deref()),
            opt(e.file_path.as_deref()),
            opt(e.file_size),
            opt(e.entry_type),
            opt(e.flags),
            opt(e.access_count),
            time(e.created),
            time(e.modified),
            time(e.accessed),
            time(e.expires),
            time(e.synced),
            opt(e.sync_count),
            opt(e.request_headers.as_deref().map(|h| h.chars().count())),
            opt(response.and_then(|h| h.lines().next())),
            opt(response.map(|h| h.chars().count())),
            opt(e.redirect_url.as_deref()),
        ]);
    }
    for c in &cache.cookies {
        line(vec![
            "cookie".into(),
            escape(&c.table),
            opt(c.directory.as_deref()),
            c.id.to_string(),
            escape(&c.host),
            escape(&c.path),
            escape(&c.name),
            escape(&c.value),
            time(c.expires),
            time(c.modified),
            opt(c.flags),
        ]);
    }
    lines
}

#[test]
fn every_row_as_dissect_reads_it() {
    let oracle = std::fs::read(format!(
        "{}/tests/oracle/webcache.tsv.gz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mut text = String::new();
    common::gzip::Decoder::new(oracle.as_slice())
        .read_to_string(&mut text)
        .unwrap();
    let mut expected: Vec<&str> = text.lines().collect();
    let mut ours: Vec<String> = FILES
        .iter()
        .flat_map(|name| lines(name, &webcache(name)))
        .collect();
    expected.sort_unstable();
    ours.sort_unstable();
    assert_eq!(ours.len(), 4_156);
    let missing: Vec<_> = expected
        .iter()
        .filter(|line| ours.binary_search_by(|o| o.as_str().cmp(line)).is_err())
        .take(3)
        .collect();
    assert!(missing.is_empty(), "{missing:#?}");
    assert_eq!(ours, expected);
}

#[test]
fn counts_and_problems() {
    for (name, containers, visits, downloads, entries, cookies) in [
        (FILES[0], 21, 113, 2, 1_434, 0),
        (FILES[1], 23, 69, 4, 2_320, 170),
    ] {
        let cache = webcache(name);
        assert_eq!(cache.containers.len(), containers, "{name}");
        assert_eq!(cache.visits.len(), visits, "{name}");
        assert_eq!(cache.downloads.len(), downloads, "{name}");
        assert_eq!(cache.entries.len(), entries, "{name}");
        assert_eq!(cache.cookies.len(), cookies, "{name}");
        // the PartitionsEx file is dirty; its three containers without a table are not problems
        assert!(
            cache.problems.iter().all(|p| p.contains("dirty")),
            "{name}: {:?}",
            cache.problems
        );
    }
}

/// Internet Explorer 11's downloads and legacy Edge's: URL, paths, size, start, referrer, MIME
/// type and publisher from the binary record.
#[test]
fn downloads() {
    let cache = webcache(FILES[0]);
    let ie = &cache.downloads[0];
    assert_eq!(ie.container, 14);
    assert_eq!(ie.download.id, 1);
    assert_eq!(
        ie.download.url,
        "https://googledrive.com/host/0B3fBvzttpiiSWFFkSTBOUHdjOVU/Windows%20SuperFetch%20(DB)%20format.pdf"
    );
    assert_eq!(
        ie.download.target_path,
        r"C:\Users\test\Downloads\Windows SuperFetch (DB) format.pdf"
    );
    assert_eq!(
        ie.download.current_path.as_deref(),
        Some(
            r"C:\Users\test\AppData\Local\Microsoft\Windows\INetCache\Low\IE\0H5ICNJW\Windows%20SuperFetch%20(DB)%20format[1].pdf"
        )
    );
    assert_eq!(ie.download.total_bytes, Some(241_651));
    assert_eq!(ie.download.mime_type.as_deref(), Some("application/pdf"));
    assert_eq!(
        ie.download.referrer.as_deref(),
        Some("http://www.forensicswiki.org/wiki/Windows_SuperFetch_Format")
    );
    assert_eq!(ie.publisher, None);
    assert_eq!(time(ie.download.start), "2014-05-12T07:33:03.0377732Z");

    let cache = webcache(FILES[1]);
    let putty = cache
        .downloads
        .iter()
        .find(|d| d.download.target_path.ends_with("putty.exe"))
        .unwrap();
    assert_eq!(
        putty.download.url,
        "https://the.earth.li/~sgtatham/putty/0.73/w64/putty.exe"
    );
    assert_eq!(putty.download.total_bytes, Some(1_179_024));
    assert_eq!(putty.publisher.as_deref(), Some("Simon Tatham"));
    assert_eq!(
        putty.download.referrer.as_deref(),
        Some("https://www.chiark.greenend.org.uk/~sgtatham/putty/releases/0.73.html")
    );
    assert!(
        putty
            .download
            .current_path
            .as_deref()
            .is_some_and(|p| p.ends_with(r"TempState\Downloads\putty.exe.j11qakb.partial"))
    );
    assert_eq!(time(putty.download.start), "2019-12-16T21:03:47.4767445Z");
    // read() gives the downloads with the visits
    let history = read(
        &support::fixture("plaso/PartitionsEx-WebCacheV01.dat.gz"),
        &[],
    )
    .unwrap();
    assert_eq!(history.kind, Kind::WebCache);
    assert_eq!(history.downloads.len(), 4);
    assert!(history.downloads.iter().any(|d| d == &putty.download));
}

/// Cached files with where they are on the disk, cookie files with their account, the cookies of
/// `CookieEntryEx` tables with whose they are.
#[test]
fn entries_and_cookies() {
    let cache = webcache(FILES[0]);
    let widgets = cache
        .entries
        .iter()
        .find(|e| e.url == "http://platform.twitter.com/widgets.js")
        .unwrap();
    assert_eq!(widgets.container_name, "Content");
    assert_eq!(widgets.file_name.as_deref(), Some("widgets[1].js"));
    assert_eq!(
        widgets.file_path.as_deref(),
        Some(
            r"C:\Users\test\AppData\Local\Microsoft\Windows\INetCache\Low\IE\SLTWV5F0\widgets[1].js"
        )
    );
    assert_eq!(widgets.file_size, Some(98_240));
    assert!(
        widgets.response_headers.as_deref().is_some_and(
            |h| h.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/javascript")
        )
    );
    let cookie_file = cache
        .entries
        .iter()
        .find(|e| e.url == "Cookie:test@microsoft.com/")
        .unwrap();
    assert_eq!(cookie_file.container_name, "Cookies");
    assert_eq!(cookie_file.user.as_deref(), Some("test"));
    assert_eq!(
        cookie_file.file_path.as_deref(),
        Some(r"C:\Users\test\AppData\Local\Microsoft\Windows\INetCookies\VLR48FYL.txt")
    );
    // compatibility list entries keep no file and no HTTP headers
    let compat = cache
        .entries
        .iter()
        .find(|e| e.container_name == "iecompat")
        .unwrap();
    assert_eq!(compat.file_path, None);
    assert_eq!(compat.response_headers, None);

    let cache = webcache(FILES[1]);
    let market = cache
        .cookies
        .iter()
        .find(|c| c.table == "CookieEntryEx_18" && c.name == "sptmarket")
        .unwrap();
    assert_eq!(market.host, "www.msn.com");
    assert_eq!(market.path, "/");
    assert_eq!(market.value, "en-us|fr|FR|en-us|en-us|en");
    assert_eq!(time(market.modified), "2019-12-16T20:54:41.8888980Z");
    let edge = cache
        .cookies
        .iter()
        .find(|c| c.table == "CookieEntryEx_13")
        .unwrap();
    assert!(
        edge.directory
            .as_deref()
            .is_some_and(|d| d.ends_with(r"\AC\#!001\MicrosoftEdge\Cookies\ESE\")),
        "{:?}",
        edge.directory
    );
}
