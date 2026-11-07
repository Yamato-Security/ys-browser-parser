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

//! Pages by number: from the write-ahead log when it committed one, else
//! from the database file.

use std::collections::HashMap;

/// Allow small gaps while keeping a damaged export proportional to its input.
pub(crate) const MAX_IMAGE_PAGE_EXPANSION: u32 = 2;

/// The database's pages, borrowed from the file and the log.
pub(crate) struct Pages<'a> {
    file: &'a [u8],
    wal: HashMap<u32, &'a [u8]>,
    page_size: usize,
    usable_size: usize,
    count: u32,
}

impl<'a> Pages<'a> {
    pub(crate) fn new(
        file: &'a [u8],
        wal: HashMap<u32, &'a [u8]>,
        page_size: u32,
        usable_size: u32,
        count: u32,
    ) -> Self {
        Self {
            file,
            wal,
            page_size: page_size as usize,
            usable_size: usable_size as usize,
            count,
        }
    }

    /// Bytes of each page that hold data (the rest is reserved).
    pub(crate) fn usable_size(&self) -> usize {
        self.usable_size
    }

    /// The database file's own copies of the pages the log replaces, in
    /// page order, usable bytes only: older versions of those pages.
    pub(crate) fn replaced_file_pages(&self) -> Vec<(u32, &'a [u8])> {
        let mut numbers: Vec<u32> = self.wal.keys().copied().collect();
        numbers.sort_unstable();
        numbers
            .into_iter()
            .filter_map(|number| {
                let page = self.file_page(number).ok()?;
                Some((number, &page[..self.usable_size]))
            })
            .collect()
    }

    /// Page `number`'s usable bytes, or why it can't be read.
    pub(crate) fn get(&self, number: u32) -> Result<&'a [u8], String> {
        if number == 0 || number > self.count {
            return Err(format!(
                "page {number} is outside the database's {} pages",
                self.count
            ));
        }
        let page = match self.wal.get(&number) {
            Some(page) => page,
            None => self.file_page(number)?,
        };
        Ok(&page[..self.usable_size])
    }

    /// Every page, whole, in order: from the log when it committed one,
    /// else from the file; zeros for a page neither holds (a truncated
    /// file). The export's size stays proportional to the supplied pages,
    /// whatever a damaged header or commit frame claims.
    pub(crate) fn image(&self) -> Vec<u8> {
        let in_file = u32::try_from(self.file.len() / self.page_size).unwrap_or(u32::MAX);
        let last_logged = self.wal.keys().copied().max().unwrap_or(0);
        let logged_pages = u32::try_from(self.wal.len()).unwrap_or(u32::MAX);
        let available = in_file.saturating_add(logged_pages);
        let limit = available.saturating_mul(MAX_IMAGE_PAGE_EXPANSION);
        let count = self.count.min(in_file.max(last_logged)).min(limit);
        let mut image = Vec::with_capacity(count as usize * self.page_size);
        for number in 1..=count {
            match self
                .wal
                .get(&number)
                .copied()
                .or_else(|| self.file_page(number).ok())
            {
                Some(page) => image.extend_from_slice(page),
                None => image.resize(image.len() + self.page_size, 0),
            }
        }
        image
    }

    fn file_page(&self, number: u32) -> Result<&'a [u8], String> {
        // Checked: on 32-bit targets a far page's offset overflows `usize`.
        let start = (number as usize - 1).checked_mul(self.page_size);
        let end = start.and_then(|start| start.checked_add(self.page_size));
        start
            .zip(end)
            .and_then(|(start, end)| self.file.get(start..end))
            .ok_or_else(|| format!("page {number} is past the end of the file (truncated)"))
    }
}
