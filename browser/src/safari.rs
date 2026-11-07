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

//! Safari's history: `History.db` (macOS 10.10 and later: `history_items`,
//! one per page, and `history_visits`, one per visit, its time in Cocoa
//! seconds, its title, the visit it was redirected from) and the older
//! `History.plist` (`WebHistoryDates`: each page's URL, title, visit count
//! and last visit, Cocoa seconds as text); and its downloads
//! (`Downloads.plist`: `DownloadHistory`, each URL, path, size, start and
//! end).

use std::collections::HashMap;

use common::time::Ts;
use plist::Value;
use sqlite::Database;

use crate::table::{self, Named};
use crate::{Download, Page, Transition, Visit};

/// Every visit of a `History.db`, with its page.
pub(crate) fn history_db(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<Visit> {
    let pages: HashMap<i64, Page> = table::read(db, "history_items", problems, |row| {
        let page = Page {
            id: row.integer("id").unwrap_or(row.rowid),
            url: row.text("url").unwrap_or_default(),
            visit_count: row.integer("visit_count"),
            ..Page::default()
        };
        (page.id, page)
    })
    .into_iter()
    .collect();
    table::read_joined(
        db,
        ("history_visits", "history_item"),
        ("history_items", &pages),
        problems,
        visit,
    )
}

fn visit(row: &Named<'_>, page: &Page) -> Visit {
    Visit {
        id: row.integer("id").unwrap_or(row.rowid),
        table: "history_visits".to_owned(),
        time: row
            .real("visit_time")
            .filter(|t| t.is_finite())
            .map(Ts::from_cocoa_seconds),
        url: page.url.clone(),
        title: row.text("title").unwrap_or_default(),
        user: None,
        transition: Transition::NotRecorded,
        from_visit: row.reference("redirect_source"),
        duration: None,
        visit_count: page.visit_count,
        typed: false,
        typed_count: None,
        hidden: false,
        frecency: None,
    }
}

/// Every page of a `History.plist`, as a visit at its last visit time.
pub(crate) fn history_plist(data: &[u8], problems: &mut Vec<String>) -> Vec<Visit> {
    let root = match plist::parse(data) {
        Ok(parsed) => parsed.value,
        Err(why) => {
            problems.push(format!("not a property list: {why}"));
            return Vec::new();
        }
    };
    let Some(dates) = root.get("WebHistoryDates").and_then(Value::as_array) else {
        problems.push("no WebHistoryDates".to_owned());
        return Vec::new();
    };
    (0i64..)
        .zip(dates)
        .map(|(index, item)| {
            let text = |key: &str| item.get(key).and_then(Value::as_str).map(str::to_owned);
            Visit {
                id: index,
                table: "WebHistoryDates".to_owned(),
                time: text("lastVisitedDate")
                    .and_then(|t| t.parse::<f64>().ok())
                    .filter(|t| t.is_finite())
                    .map(Ts::from_cocoa_seconds),
                url: text("").unwrap_or_default(),
                title: text("title").unwrap_or_default(),
                user: None,
                transition: Transition::NotRecorded,
                from_visit: None,
                duration: None,
                visit_count: item.get("visitCount").and_then(Value::as_i64),
                typed: false,
                typed_count: None,
                hidden: false,
                frecency: None,
            }
        })
        .collect()
}

/// Every download of a `Downloads.plist`.
pub(crate) fn downloads(data: &[u8], problems: &mut Vec<String>) -> Vec<Download> {
    let root = match plist::parse(data) {
        Ok(parsed) => parsed.value,
        Err(why) => {
            problems.push(format!("not a property list: {why}"));
            return Vec::new();
        }
    };
    let Some(history) = root.get("DownloadHistory").and_then(Value::as_array) else {
        problems.push("no DownloadHistory".to_owned());
        return Vec::new();
    };
    (0i64..)
        .zip(history)
        .map(|(index, item)| {
            let text = |key: &str| item.get(key).and_then(Value::as_str).map(str::to_owned);
            let url = text("DownloadEntryURL").unwrap_or_default();
            Download {
                id: index,
                url_chain: vec![url.clone()],
                url,
                target_path: text("DownloadEntryPath").unwrap_or_default(),
                current_path: text("DownloadEntryPostPath"),
                start: item
                    .get("DownloadEntryDateAddedKey")
                    .and_then(Value::as_date),
                end: item
                    .get("DownloadEntryDateFinishedKey")
                    .and_then(Value::as_date),
                received_bytes: item
                    .get("DownloadEntryProgressBytesSoFar")
                    .and_then(Value::as_i64),
                total_bytes: item
                    .get("DownloadEntryProgressTotalToLoad")
                    .and_then(Value::as_i64),
                state: None,
                danger_type: None,
                interrupt_reason: None,
                referrer: None,
                tab_url: None,
                mime_type: None,
                opened: None,
                deleted: None,
            }
        })
        .collect()
}
