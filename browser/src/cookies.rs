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

//! Cookies: Chromium's `Cookies` (table `cookies`; times in `WebKit`
//! microseconds, `secure`/`httponly` renamed `is_secure`/`is_httponly` in
//! Chrome 66) and Firefox's `cookies.sqlite` (table `moz_cookies`;
//! creation and last access in Unix microseconds, expiry in seconds); and
//! Safari's, in a file of their own (`binarycookies`). The value is read
//! as stored: Chromium encrypts it (`encrypted_value`) since Chrome 80, and
//! that isn't decrypted. Google Analytics' cookies are decoded
//! (`analytics`).

use common::time::Ts;
use sqlite::Database;

use crate::analytics::{self, GoogleAnalytics};
use crate::table::{self, Named};

/// Which browser a cookie is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieStore {
    /// Chromium (Chrome, Edge, Brave, Opera, Vivaldi).
    Chromium,
    /// Firefox.
    Firefox,
    /// Safari (`Cookies.binarycookies`).
    Safari,
}

/// A cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// Which browser.
    pub store: CookieStore,
    /// The row id; for Safari, where its record starts in the file.
    pub rowid: i64,
    /// The host it's for (`.example.com`).
    pub host: String,
    /// Its name.
    pub name: String,
    /// Its value, as stored (empty when Chromium encrypted it).
    pub value: String,
    /// The path it's for.
    pub path: String,
    /// When it was set.
    pub created: Option<Ts>,
    /// When it was last sent.
    pub last_accessed: Option<Ts>,
    /// When it expires; `None` for a session cookie.
    pub expires: Option<Ts>,
    /// Sent over HTTPS only.
    pub secure: bool,
    /// Hidden from scripts.
    pub http_only: bool,
    /// Kept across sessions (Chromium).
    pub persistent: Option<bool>,
    /// What its value says, when it is a Google Analytics cookie
    /// (`__utma`, `__utmb`, `__utmt`, `__utmz`).
    pub analytics: Option<GoogleAnalytics>,
}

/// Every cookie of a cookie database, Google Analytics' decoded.
pub(crate) fn read(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<Cookie> {
    let mut cookies = if db.table("cookies").is_some() {
        table::read(db, "cookies", problems, chromium)
    } else {
        table::read(db, "moz_cookies", problems, firefox)
    };
    analytics::decode_all(&mut cookies, problems);
    cookies
}

fn chromium(row: &Named<'_>) -> Cookie {
    let flag = |new: &str, old: &str| row.flag(new).or_else(|| row.flag(old));
    let webkit = |column: &str| {
        row.integer(column)
            .filter(|&t| t != 0)
            .map(Ts::from_webkit_micros)
    };
    let has_expires = row.flag("has_expires").unwrap_or(true);
    Cookie {
        store: CookieStore::Chromium,
        rowid: row.rowid,
        host: row.text("host_key").unwrap_or_default(),
        name: row.text("name").unwrap_or_default(),
        value: row.text("value").unwrap_or_default(),
        path: row.text("path").unwrap_or_default(),
        created: webkit("creation_utc"),
        last_accessed: webkit("last_access_utc"),
        expires: webkit("expires_utc").filter(|_| has_expires),
        secure: flag("is_secure", "secure").unwrap_or(false),
        http_only: flag("is_httponly", "httponly").unwrap_or(false),
        persistent: flag("is_persistent", "persistent"),
        analytics: None,
    }
}

fn firefox(row: &Named<'_>) -> Cookie {
    let micros = |column: &str| {
        row.integer(column)
            .filter(|&t| t != 0)
            .map(Ts::from_unix_micros)
    };
    Cookie {
        store: CookieStore::Firefox,
        rowid: row.rowid,
        host: row.text("host").unwrap_or_default(),
        name: row.text("name").unwrap_or_default(),
        value: row.text("value").unwrap_or_default(),
        path: row.text("path").unwrap_or_default(),
        created: micros("creationTime"),
        last_accessed: micros("lastAccessed"),
        expires: row
            .integer("expiry")
            .filter(|&t| t != 0)
            .map(Ts::from_unix_seconds),
        secure: row.flag("isSecure").unwrap_or(false),
        http_only: row.flag("isHttpOnly").unwrap_or(false),
        persistent: None,
        analytics: None,
    }
}
