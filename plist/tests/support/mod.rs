// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/plist (https://github.com/Sootmark/plist), whose code
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

//! Shared by the integration tests: fixtures, the oracle's dumps, and
//! values written the way the oracle writes them.

#![allow(dead_code)] // Each test crate uses its own part of this module.

use std::fs;
use std::path::{Path, PathBuf};

use common::json::{self, Json};
use plist::Value;

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// A fixture's bytes (`tests/fixtures/<path>`).
pub fn fixture(path: &str) -> Vec<u8> {
    fs::read(tests_dir().join("fixtures").join(path)).unwrap()
}

/// Every fixture with an oracle dump: (fixture path, the dump).
pub fn oracle_fixtures() -> Vec<(String, Json)> {
    let mut all = Vec::new();
    for directory in ["generated", "authored", "plaso"] {
        let dir = tests_dir().join("oracle").join(directory);
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            let Some(fixture) = name.strip_suffix(".json") else {
                continue;
            };
            let dump = json::parse(&fs::read_to_string(&path).unwrap()).unwrap();
            all.push((format!("{directory}/{fixture}"), dump));
        }
    }
    all.sort_by(|a, b| a.0.cmp(&b.0));
    all
}

/// A value as the oracle dumps it (see `tests/oracle/gen.py`).
pub fn typed(value: &Value) -> Json {
    let (tag, json) = match value {
        Value::Dictionary(entries) => (
            "dict",
            Json::Array(
                entries
                    .iter()
                    .map(|(key, value)| Json::Array(vec![Json::String(key.clone()), typed(value)]))
                    .collect(),
            ),
        ),
        Value::Array(elements) => ("array", Json::Array(elements.iter().map(typed).collect())),
        Value::String(text) => ("string", Json::String(text.clone())),
        Value::Integer(integer) => ("integer", Json::String(integer.to_string())),
        Value::Real(real) => ("real", Json::String(format!("{:016x}", real.to_bits()))),
        Value::Bool(value) => ("bool", Json::Bool(*value)),
        Value::Date(date) => ("date", Json::String(microseconds(date))),
        Value::Data(bytes) => ("data", Json::String(hex(bytes))),
        Value::Uid(index) => ("uid", number(*index)),
        Value::Null => ("null", Json::Null),
    };
    Json::object([(tag, json)])
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ`: six fraction digits, as Python writes.
fn microseconds(date: &plist::Ts) -> String {
    let iso = date.to_iso8601().expect("a time");
    let (seconds, tenth_of_microsecond) = iso.split_at(iso.len() - 2);
    assert_eq!(tenth_of_microsecond, "0Z", "{iso}");
    format!("{seconds}Z")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn number(value: u64) -> Json {
    i64::try_from(value).map_or(Json::UInt(value), Json::Int)
}

/// Where two dumps first differ, as a path from the top; `None` if equal.
pub fn first_difference(ours: &Json, oracle: &Json, path: &str) -> Option<String> {
    match (ours, oracle) {
        (Json::Array(a), Json::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!("{path}: {} elements, oracle {}", a.len(), b.len()));
            }
            a.iter()
                .zip(b)
                .enumerate()
                .find_map(|(index, (a, b))| first_difference(a, b, &format!("{path}[{index}]")))
        }
        (Json::Object(a), Json::Object(b)) if a.len() == b.len() => {
            a.iter().zip(b).find_map(|((ka, va), (kb, vb))| {
                if ka == kb {
                    first_difference(va, vb, &format!("{path}.{ka}"))
                } else {
                    Some(format!("{path}: {ka}, oracle {kb}"))
                }
            })
        }
        _ if ours == oracle => None,
        _ => Some(format!("{path}: {ours:?}, oracle {oracle:?}")),
    }
}

/// The scalar values in a dump (containers not counted).
pub fn count_scalars(dump: &Json) -> usize {
    match dump {
        Json::Object(members) => match members.as_slice() {
            [(tag, Json::Array(items))] if tag == "dict" => items
                .iter()
                .map(|pair| pair.as_array().map_or(0, |pair| count_scalars(&pair[1])))
                .sum(),
            [(tag, Json::Array(items))] if tag == "array" => items.iter().map(count_scalars).sum(),
            _ => 1,
        },
        _ => 0,
    }
}

/// Dictionaries' entries sorted by key, all the way down (CoreFoundation's
/// binary writer orders keys by hash).
pub fn sort_keys(value: &mut Value) {
    match value {
        Value::Dictionary(entries) => {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, value) in entries.iter_mut() {
                sort_keys(value);
            }
        }
        Value::Array(elements) => elements.iter_mut().for_each(sort_keys),
        _ => {}
    }
}
