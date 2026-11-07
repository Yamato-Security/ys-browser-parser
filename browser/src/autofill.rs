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

//! Form history: each value typed in a form field, by the field's name, how
//! many times, and when first and last — accounts, e-mail addresses,
//! searches a user typed. Chromium keeps it in `Web Data` (table `autofill`,
//! Unix seconds), Firefox in `formhistory.sqlite` (table `moz_formhistory`,
//! microseconds; with each entry's GUID, the sources newer versions record,
//! and `moz_deleted_formhistory`'s record of removed entries).

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

use common::time::Ts;
use sqlite::{Confidence, Database, Value};

use crate::Provenance;
use crate::recovered::{self, Found, Recovery};
use crate::table::{self, Named};

/// Which browser a form history comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormStore {
    /// Chromium's `Web Data` (Chrome, Edge, Brave, Opera, Vivaldi).
    Chromium,
    /// Firefox's `formhistory.sqlite`.
    Firefox,
}

/// A value typed in a form field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutofillEntry {
    /// Which browser's form history it is in.
    pub store: FormStore,
    /// The row id.
    pub rowid: i64,
    /// The field's name (`email`, `q`, `identifier`; Firefox's search bar:
    /// `searchbar-history`).
    pub field: String,
    /// What was typed.
    pub value: String,
    /// How many times.
    pub count: Option<i64>,
    /// When first.
    pub created: Option<Ts>,
    /// When last.
    pub last_used: Option<Ts>,
    /// Firefox: the entry's GUID, by which Sync and
    /// [`FormRemoval`]s name it.
    pub guid: Option<String>,
    /// Firefox: where the entry was saved from (`moz_sources`, in the
    /// versions that have it), as stored.
    pub sources: Vec<String>,
}

/// Firefox's record of a removed form history entry
/// (`moz_deleted_formhistory`): which entry, by GUID, and when. The entry
/// itself is gone; [`FormHistory::deleted`] may still hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormRemoval {
    /// The row id.
    pub rowid: i64,
    /// The removed entry's GUID.
    pub guid: String,
    /// When it was removed.
    pub time: Option<Ts>,
}

/// A deleted form history entry the database still holds, with where it
/// was recovered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFormEntry {
    /// The entry; a value whose bytes were lost reads empty or `None`
    /// (see [`Provenance::lost`]).
    pub entry: AutofillEntry,
    /// Where it was found, and how sure.
    pub provenance: Provenance,
}

/// A form history database read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormHistory {
    /// Which browser's.
    pub store: FormStore,
    /// The entries, in row order.
    pub entries: Vec<AutofillEntry>,
    /// Deleted entries the database and its log still hold: not live, and
    /// not an earlier version of a live entry (same field and value).
    pub deleted: Vec<RecoveredFormEntry>,
    /// Firefox: the removals it recorded.
    pub removals: Vec<FormRemoval>,
    /// Damage met, and what recovery met (`recovery: …`).
    pub problems: Vec<String>,
}

const FIREFOX: &str = "moz_formhistory";
const CHROMIUM: &str = "autofill";

fn store(db: &Database<'_>) -> FormStore {
    if db.table(FIREFOX).is_some() {
        FormStore::Firefox
    } else {
        FormStore::Chromium
    }
}

/// Every entry of a `Web Data` or `formhistory.sqlite` database.
pub(crate) fn read(db: &Database<'_>, problems: &mut Vec<String>) -> Vec<AutofillEntry> {
    match store(db) {
        FormStore::Chromium => table::read(db, CHROMIUM, problems, chromium_entry),
        FormStore::Firefox => {
            let sources = firefox_sources(db, problems);
            let mut entries = table::read(db, FIREFOX, problems, firefox_entry);
            for entry in &mut entries {
                if let Some(found) = sources.get(&entry.rowid) {
                    entry.sources.clone_from(found);
                }
            }
            entries
        }
    }
}

/// The entries, the deleted ones still held, and Firefox's removals.
pub(crate) fn history(
    db: &Database<'_>,
    recovery: &Recovery,
    mut problems: Vec<String>,
) -> FormHistory {
    let store = store(db);
    let entries = read(db, &mut problems);
    let (table, convert): (&str, fn(&Named<'_>) -> AutofillEntry) = match store {
        FormStore::Chromium => (CHROMIUM, chromium_entry),
        FormStore::Firefox => (FIREFOX, firefox_entry),
    };
    let live: HashSet<(String, String)> = entries.iter().filter_map(key).collect();
    let deleted = recovered::deleted(recovery.read(db, table, convert), key, &live, rank)
        .into_iter()
        .map(|Found { entry, provenance }| RecoveredFormEntry { entry, provenance })
        .collect();
    let removals = match store {
        FormStore::Firefox => table::read(db, "moz_deleted_formhistory", &mut problems, removal),
        FormStore::Chromium => Vec::new(),
    };
    FormHistory {
        store,
        entries,
        deleted,
        removals,
        problems,
    }
}

/// What identifies an entry: both browsers keep one row per field and value.
fn key(entry: &AutofillEntry) -> Option<(String, String)> {
    (!entry.field.is_empty() && !entry.value.is_empty())
        .then(|| (entry.field.clone(), entry.value.clone()))
}

/// Of several copies of one deleted entry: the best recovered, then the
/// latest used.
fn rank(found: &Found<AutofillEntry>) -> ((Confidence, u8, Reverse<usize>), Option<i64>) {
    (
        recovered::strength(&found.provenance),
        found.entry.last_used.and_then(|t| t.ticks()),
    )
}

fn chromium_entry(row: &Named<'_>) -> AutofillEntry {
    let seconds = |column: &str| {
        row.integer(column)
            .filter(|&t| t != 0)
            .map(Ts::from_unix_seconds)
    };
    AutofillEntry {
        store: FormStore::Chromium,
        rowid: row.rowid,
        field: row.text("name").unwrap_or_default(),
        value: row.text("value").unwrap_or_default(),
        count: row.integer("count"),
        created: seconds("date_created"),
        last_used: seconds("date_last_used"),
        guid: None,
        sources: Vec::new(),
    }
}

fn micros(row: &Named<'_>, column: &str) -> Option<Ts> {
    row.integer(column)
        .filter(|&t| t != 0)
        .map(Ts::from_unix_micros)
}

fn firefox_entry(row: &Named<'_>) -> AutofillEntry {
    AutofillEntry {
        store: FormStore::Firefox,
        rowid: row.rowid,
        field: row.text("fieldname").unwrap_or_default(),
        value: row.text("value").unwrap_or_default(),
        count: row.integer("timesUsed"),
        created: micros(row, "firstUsed"),
        last_used: micros(row, "lastUsed"),
        guid: row.text("guid"),
        sources: Vec::new(),
    }
}

fn removal(row: &Named<'_>) -> FormRemoval {
    FormRemoval {
        rowid: row.rowid,
        guid: row.text("guid").unwrap_or_default(),
        time: micros(row, "timeDeleted"),
    }
}

/// Each entry's sources, by entry id: `moz_history_to_sources` (a
/// `WITHOUT ROWID` table: entry id, source id) joined to `moz_sources`.
fn firefox_sources(db: &Database<'_>, problems: &mut Vec<String>) -> HashMap<i64, Vec<String>> {
    let mut by_entry: HashMap<i64, Vec<String>> = HashMap::new();
    if db.table("moz_history_to_sources").is_none() {
        return by_entry;
    }
    let names: HashMap<i64, String> = table::read(db, "moz_sources", problems, |row| {
        (row.rowid, row.text("source").unwrap_or_default())
    })
    .into_iter()
    .collect();
    let mut links = match db.index_entries("moz_history_to_sources") {
        Ok(links) => links,
        Err(e) => {
            problems.push(format!("moz_history_to_sources: {e}"));
            return by_entry;
        }
    };
    for link in links.by_ref() {
        let id = |at: usize| link.values.get(at).and_then(Value::as_integer);
        let (Some(entry), Some(source)) = (id(0), id(1)) else {
            problems.push("moz_history_to_sources: an entry without its two ids".to_owned());
            continue;
        };
        match names.get(&source) {
            Some(name) => by_entry.entry(entry).or_default().push(name.clone()),
            None => problems.push(format!(
                "moz_history_to_sources: entry {entry} names source {source}, which moz_sources lacks"
            )),
        }
    }
    problems.extend(
        links
            .problems()
            .iter()
            .map(|p| format!("moz_history_to_sources: {p}")),
    );
    by_entry
}
