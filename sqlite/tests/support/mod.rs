// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/sqlite (https://github.com/Sootmark/sqlite), whose code
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

//! Shared by the integration tests: fixtures, the oracle's JSON, and a
//! walk through everything a database holds.

#![allow(dead_code)] // Each test crate uses its own part of this module.

use std::fs;
use std::path::{Path, PathBuf};

use sqlite::{Database, TableKind, Value};

pub mod json;

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// A fixture's bytes (`tests/fixtures/<name>`).
pub fn fixture(name: &str) -> Vec<u8> {
    fs::read(tests_dir().join("fixtures").join(name)).unwrap()
}

/// The oracle files of one fixture: (object name, rows), sorted by name.
pub fn oracle(fixture: &str) -> Vec<(String, Vec<json::Row>)> {
    let mut objects: Vec<_> = fs::read_dir(tests_dir().join("oracle").join(fixture))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            (name, json::rows(&fs::read_to_string(&path).unwrap()))
        })
        .collect();
    objects.sort_by(|a, b| a.0.cmp(&b.0));
    objects
}

/// An oracle value, `"type:value"` or null, as the value it describes.
pub fn oracle_value(value: &json::Value) -> Value {
    let text = match value {
        json::Value::Null => return Value::Null,
        json::Value::Integer(integer) => return Value::Integer(*integer),
        json::Value::Text(text) => text,
    };
    let (kind, value) = text.split_once(':').unwrap();
    match kind {
        "integer" => Value::Integer(value.parse().unwrap()),
        "real" => Value::Real(value.parse().unwrap()),
        "text" => Value::Text(value.to_owned()),
        "blob" => Value::Blob(
            (0..value.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
                .collect(),
        ),
        _ => panic!("oracle value of unknown type: {text}"),
    }
}

/// What a walk through a whole database found.
#[derive(Debug, Default)]
pub struct Walk {
    pub rows: usize,
    pub index_entries: usize,
    /// Records recovered, current and older versions.
    pub recovered: usize,
    pub problems: Vec<String>,
}

/// Read every row of every rowid table and every entry of every index,
/// and recover deleted records, as a reader of untrusted evidence would.
pub fn walk(db: &Database) -> Walk {
    // Whole pages, however damaged the input.
    assert_eq!(db.image().len() % db.header.page_size as usize, 0);
    let mut walk = Walk {
        problems: db.problems.clone(),
        ..Walk::default()
    };
    for table in db.tables.iter().filter(|t| t.kind == TableKind::Rowid) {
        let mut rows = db.rows(&table.name).unwrap();
        walk.rows += rows.by_ref().count();
        walk.problems.extend_from_slice(rows.problems());
    }
    for entry in &db.schema {
        if let Ok(mut entries) = db.index_entries(&entry.name) {
            walk.index_entries += entries.by_ref().count();
            walk.problems.extend_from_slice(entries.problems());
        }
    }
    let recovered = db.recover();
    walk.recovered = recovered.records.len() + recovered.older_versions.len();
    walk.problems.extend(recovered.problems);
    walk
}
