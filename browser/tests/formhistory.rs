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
//! Form history: Firefox's `formhistory.sqlite` (and Chromium's `Web Data`
//! read the same way). The fixtures are made by
//! `tests/fixtures/formhistory/gen.sh` (Firefox 140's tables, synthetic
//! rows); `Web Data` is plaso's.

mod support;

use browser::{
    Area, AutofillEntry, Confidence, FormStore, Kind, PageState, detect, read_autofill,
    read_form_history,
};
use support::fixture;

/// 2026-09-01 08:00:00 UTC in microseconds, as the generator writes it.
const T0: i64 = 1_788_249_600_000_000;

fn micros(t: Option<common::time::Ts>) -> Option<i64> {
    t.and_then(|t| t.ticks()).map(|ticks| ticks / 10)
}

fn find<'e>(entries: &'e [AutofillEntry], field: &str, value: &str) -> &'e AutofillEntry {
    entries
        .iter()
        .find(|e| e.field == field && e.value == value)
        .unwrap_or_else(|| panic!("no {field}: {value}"))
}

#[test]
fn firefox_form_history_is_detected() {
    let data = fixture("formhistory/formhistory.sqlite");
    assert_eq!(detect("formhistory.sqlite", &data), Some(Kind::Autofill));
    assert_eq!(
        detect("copy.db", &data),
        Some(Kind::Autofill),
        "by its tables"
    );
    assert_eq!(Kind::from_name("formhistory.sqlite"), Some(Kind::Autofill));
}

#[test]
fn entries_sources_removals_and_a_deleted_entry() {
    let history = read_form_history(&fixture("formhistory/formhistory.sqlite"), &[]).unwrap();
    assert!(history.problems.is_empty(), "{:?}", history.problems);
    assert_eq!(history.store, FormStore::Firefox);
    assert_eq!(history.entries.len(), 4);

    let email = find(&history.entries, "email", "alice@example.com");
    assert_eq!(email.store, FormStore::Firefox);
    assert_eq!(email.rowid, 1);
    assert_eq!(email.count, Some(2));
    assert_eq!(
        micros(email.created),
        Some(T0 + 123_456),
        "to the microsecond"
    );
    assert_eq!(micros(email.last_used), Some(T0 + 3_600_000_789));
    assert_eq!(email.guid.as_deref(), Some("GuIdEmAiL0000001"));
    assert!(email.sources.is_empty(), "{:?}", email.sources);

    let search = find(&history.entries, "searchbar-history", "quarterly report");
    assert_eq!(search.sources, ["Example Search", "Example Encyclopedia"]);
    let login = find(&history.entries, "searchbar-history", "example.org login");
    assert_eq!(login.sources, ["Example Search"]);

    assert_eq!(history.removals.len(), 1);
    let removal = &history.removals[0];
    assert_eq!(removal.guid, "GuIdUsErNaMe0005");
    assert_eq!(micros(removal.time), Some(T0 + 90_000_000_000));

    // The removed entry itself: secure_delete off left its record in the
    // page's free space.
    assert_eq!(history.deleted.len(), 1, "{:?}", history.deleted);
    let deleted = &history.deleted[0];
    assert_eq!(
        (deleted.entry.field.as_str(), deleted.entry.value.as_str()),
        ("username", "old-account-7")
    );
    assert_eq!(deleted.entry.count, Some(4));
    assert_eq!(micros(deleted.entry.created), Some(T0 + 30_000_000));
    assert_eq!(micros(deleted.entry.last_used), Some(T0 + 86_400_000_000));
    assert_eq!(
        deleted.entry.guid.as_deref(),
        Some(removal.guid.as_str()),
        "the removal names it"
    );
    assert_eq!(deleted.provenance.table, "moz_formhistory");
    assert_eq!(deleted.provenance.page_state, PageState::InUse);
    assert_eq!(deleted.provenance.area, Area::Unallocated);
    assert_eq!(deleted.provenance.confidence, Confidence::High);
}

#[test]
fn the_log_adds_changes_and_hides_a_removed_entry_the_file_still_holds() {
    let history = read_form_history(
        &fixture("formhistory/wal/formhistory.sqlite"),
        &fixture("formhistory/wal/formhistory.sqlite-wal"),
    )
    .unwrap();
    assert!(history.problems.is_empty(), "{:?}", history.problems);
    let mut live: Vec<(&str, &str)> = history
        .entries
        .iter()
        .map(|e| (e.field.as_str(), e.value.as_str()))
        .collect();
    live.sort_unstable();
    assert_eq!(
        live,
        [
            ("email", "alice@example.com"),
            ("phone", "+1-555-0100"),
            ("searchbar-history", "example.org login"),
            ("searchbar-history", "quarterly report"),
        ],
        "the entry added in the log, not the one it removed"
    );
    let email = find(&history.entries, "email", "alice@example.com");
    assert_eq!(email.count, Some(3), "as the log changed it");
    assert_eq!(micros(email.last_used), Some(T0 + 240_000_000));

    assert_eq!(history.removals.len(), 1);
    assert_eq!(history.removals[0].guid, "GuIdCiTy00000004");

    // The removed entry, from the file's copy of the page the log replaced;
    // the email entry's older version there is not a deleted entry.
    assert_eq!(history.deleted.len(), 1, "{:?}", history.deleted);
    let deleted = &history.deleted[0];
    assert_eq!(
        (deleted.entry.field.as_str(), deleted.entry.value.as_str()),
        ("city", "Springfield")
    );
    assert_eq!(deleted.entry.guid.as_deref(), Some("GuIdCiTy00000004"));
    assert_eq!(deleted.provenance.page_state, PageState::ReplacedInFile);
    assert_eq!(deleted.provenance.confidence, Confidence::High);

    // The file alone: the entries before the log, nothing deleted.
    let file = read_form_history(&fixture("formhistory/wal/formhistory.sqlite"), &[]).unwrap();
    assert_eq!(file.entries.len(), 4);
    assert!(file.deleted.is_empty(), "{:?}", file.deleted);
    assert!(file.removals.is_empty(), "{:?}", file.removals);
}

#[test]
fn tables_before_sources() {
    let history = read_form_history(&fixture("formhistory/old/formhistory.sqlite"), &[]).unwrap();
    assert!(history.problems.is_empty(), "{:?}", history.problems);
    assert_eq!(history.entries.len(), 2);
    assert!(history.entries.iter().all(|e| e.sources.is_empty()));
    let q = find(&history.entries, "q", "example.net weather");
    assert_eq!((q.count, micros(q.created)), (Some(2), Some(T0)));
    assert_eq!(history.removals.len(), 1);
    assert_eq!(micros(history.removals[0].time), Some(T0 + 30_000_000));
}

#[test]
fn read_autofill_reads_firefox_too() {
    let data = fixture("formhistory/formhistory.sqlite");
    let rows = read_autofill(&data, &[]).unwrap();
    assert!(rows.problems.is_empty(), "{:?}", rows.problems);
    assert_eq!(rows.rows, read_form_history(&data, &[]).unwrap().entries);
}

#[test]
fn chromium_web_data_reads_the_same_way() {
    let data = fixture("plaso/Web Data.gz");
    let history = read_form_history(&data, &[]).unwrap();
    assert_eq!(history.store, FormStore::Chromium);
    assert_eq!(history.entries, read_autofill(&data, &[]).unwrap().rows);
    assert_eq!(history.entries.len(), 3);
    assert!(
        history
            .entries
            .iter()
            .all(|e| e.store == FormStore::Chromium && e.guid.is_none() && e.sources.is_empty())
    );
    assert!(history.removals.is_empty(), "{:?}", history.removals);
    assert!(history.deleted.is_empty(), "{:?}", history.deleted);
}

#[test]
fn other_databases_are_not_form_history() {
    assert!(read_form_history(&fixture("plaso/History"), &[]).is_err());
    assert!(read_form_history(b"not a database", &[]).is_err());
}

fn lifecycle() -> browser::FormHistory {
    read_form_history(
        &fixture("formhistory/lifecycle/formhistory.sqlite"),
        &fixture("formhistory/lifecycle/formhistory.sqlite-wal"),
    )
    .unwrap()
}

#[test]
fn tombstones_keep_distinct_deleted_entries_when_the_value_is_reentered() {
    let history = lifecycle();
    assert!(history.problems.is_empty(), "{:?}", history.problems);
    let live = find(&history.entries, "searchbar-history", "incident response");
    assert_eq!(live.guid.as_deref(), Some("CycleGuidC000003"));
    let mut guids: Vec<_> = history
        .deleted
        .iter()
        .filter(|r| r.entry.field == "searchbar-history" && r.entry.value == "incident response")
        .filter_map(|r| r.entry.guid.as_deref())
        .collect();
    guids.sort_unstable();
    assert_eq!(guids, ["CycleGuidA000001", "CycleGuidB000002"]);
    assert_eq!(history.removals.len(), 2);
    for entry in &history.deleted {
        assert!(
            history
                .removals
                .iter()
                .any(|r| Some(r.guid.as_str()) == entry.entry.guid.as_deref())
        );
    }
}

#[test]
fn updating_a_live_guids_value_is_not_a_deletion() {
    let history = lifecycle();
    let current = find(&history.entries, "email", "after@example.test");
    assert_eq!(current.guid.as_deref(), Some("StableGuid000001"));
    assert!(
        !history
            .deleted
            .iter()
            .any(|r| r.entry.guid.as_deref() == Some("StableGuid000001"))
    );
}

#[test]
fn renamed_and_previously_unknown_guids_are_not_false_deletions() {
    let history = lifecycle();
    assert_eq!(
        find(&history.entries, "q", "rename-only").guid.as_deref(),
        Some("RenamedGuid00002")
    );
    assert_eq!(
        find(&history.entries, "legacy-guid", "unchanged")
            .guid
            .as_deref(),
        Some("KnownGuid0000006")
    );
    assert!(
        !history
            .deleted
            .iter()
            .any(|r| r.entry.field == "q" || r.entry.field == "legacy-guid")
    );
}
