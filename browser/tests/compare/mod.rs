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

//! Lines compared with plaso's, as many times as plaso has each.

use std::collections::BTreeMap;

/// Each line and how many times it occurs.
fn counted<'l>(lines: impl IntoIterator<Item = &'l str>) -> BTreeMap<&'l str, usize> {
    let mut counts = BTreeMap::new();
    for line in lines {
        *counts.entry(line).or_insert(0) += 1;
    }
    counts
}

/// That `got` holds the lines of `expected`, each as many times; the first
/// that differ are shown, with their counts.
pub fn assert_same_lines(got: &[String], expected: &[&str]) {
    let got = counted(got.iter().map(String::as_str));
    let expected = counted(expected.iter().copied());
    let differ = |of: &BTreeMap<&str, usize>, than: &BTreeMap<&str, usize>| {
        of.iter()
            .filter(|(line, count)| than.get(*line) != Some(count))
            .map(|(line, count)| format!("{count}x {line}"))
            .take(10)
            .collect::<Vec<_>>()
    };
    let (missing, extra) = (differ(&expected, &got), differ(&got, &expected));
    assert!(
        missing.is_empty() && extra.is_empty(),
        "expected {missing:#?}\ngot {extra:#?}"
    );
}
