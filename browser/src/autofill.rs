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

//! Chromium's form history (`Web Data`, table `autofill`): each value typed
//! in a form field, by the field's name, how many times, and when first and
//! last (Unix seconds): accounts, e-mail addresses, searches a user typed.

use common::time::Ts;
use sqlite::Database;

use crate::table::{self, Named};

/// A value typed in a form field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutofillEntry {
    /// The row id.
    pub rowid: i64,
    /// The field's name (`email`, `q`, `identifier`).
    pub field: String,
    /// What was typed.
    pub value: String,
    /// How many times.
    pub count: Option<i64>,
    /// When first.
    pub created: Option<Ts>,
    /// When last.
    pub last_used: Option<Ts>,
}

/// Every entry of a `Web Data` database.
pub(crate) fn read(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<AutofillEntry> {
    table::read(db, "autofill", problems, entry)
}

fn entry(row: &Named<'_>) -> AutofillEntry {
    let seconds = |column: &str| {
        row.integer(column)
            .filter(|&t| t != 0)
            .map(Ts::from_unix_seconds)
    };
    AutofillEntry {
        rowid: row.rowid,
        field: row.text("name").unwrap_or_default(),
        value: row.text("value").unwrap_or_default(),
        count: row.integer("count"),
        created: seconds("date_created"),
        last_used: seconds("date_last_used"),
    }
}
