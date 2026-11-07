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

//! The write-ahead log fixture (`wal.db` and `wal.db-wal`, made by
//! `tests/fixtures/gen.sh`): a log restarted after a checkpoint, holding one
//! committed transaction, the spilled frames of one that never committed,
//! and frames of earlier transactions under the old salts.

mod support;

use sqlite::{Database, Row, Value};

const WAL_HEADER_SIZE: usize = 32;
const FRAME_HEADER_SIZE: usize = 24;
const PAGE_SIZE: usize = 512;
const FRAME_SIZE: usize = FRAME_HEADER_SIZE + PAGE_SIZE;

fn files() -> (Vec<u8>, Vec<u8>) {
    (support::fixture("wal.db"), support::fixture("wal.db-wal"))
}

fn notes(db: &Database) -> Vec<Row> {
    let mut rows = db.rows("notes").unwrap();
    let notes = rows.by_ref().collect();
    assert_eq!(rows.problems(), &[] as &[String]);
    notes
}

fn body(rows: &[Row], rowid: i64) -> Option<&str> {
    let row = rows.iter().find(|row| row.rowid == rowid)?;
    row.values[1].as_text()
}

#[test]
fn the_log_holds_what_the_file_does_not() {
    let (file, wal) = files();
    let before = notes(&Database::open(&file).unwrap());
    let after = notes(&Database::open_with_wal(&file, &wal).unwrap());
    assert_eq!(body(&after, 3), Some("round two: edited in the WAL"));
    assert!(body(&before, 3).unwrap().starts_with("round one, note 3: "));
    assert!(body(&before, 4).is_some() && body(&after, 4).is_none());
    assert_eq!(
        body(&after, 25),
        Some("round two: committed to the WAL only")
    );
    assert!(
        after
            .iter()
            .all(|row| !body(&after, row.rowid).unwrap().starts_with("round three"))
    );
}

#[test]
fn the_image_reads_as_the_file_and_its_log() {
    let (file, wal) = files();
    let with_log = Database::open_with_wal(&file, &wal).unwrap();
    let image = with_log.image();
    assert_eq!(image.len(), with_log.page_count as usize * PAGE_SIZE);
    let alone = Database::open(&image).unwrap();
    assert_eq!(alone.schema, with_log.schema);
    assert_eq!(notes(&alone), notes(&with_log));
    // Without a log, the file itself.
    assert_eq!(Database::open(&file).unwrap().image(), file);
}

#[test]
fn the_summary_counts_uncommitted_and_stale_frames() {
    let (file, wal) = files();
    let db = Database::open_with_wal(&file, &wal).unwrap();
    let summary = db.wal.unwrap();
    assert!(!summary.big_endian_checksums);
    assert_eq!(summary.page_size, 512);
    assert_eq!(
        summary.total_frames,
        (wal.len() - WAL_HEADER_SIZE) / FRAME_SIZE
    );
    assert!(summary.committed_frames > 0, "{summary:?}");
    assert!(
        summary.valid_frames > summary.committed_frames,
        "uncommitted frames: {summary:?}"
    );
    assert!(
        summary.total_frames > summary.valid_frames,
        "stale frames: {summary:?}"
    );
    assert_eq!(db.page_count, summary.database_pages);
}

/// A log written on a big-endian machine (magic 0x377f0683, checksums over
/// big-endian words) reads the same.
#[test]
fn big_endian_checksums() {
    let (file, wal) = files();
    let big = big_endian_copy(&wal);
    let ours = Database::open_with_wal(&file, &big).unwrap();
    let theirs = Database::open_with_wal(&file, &wal).unwrap();
    assert!(ours.wal.as_ref().unwrap().big_endian_checksums);
    assert_eq!(
        ours.wal.as_ref().unwrap().valid_frames,
        theirs.wal.as_ref().unwrap().valid_frames
    );
    assert_eq!(notes(&ours), notes(&theirs));
}

/// A damaged byte in the last committed frame ends the log before it: the
/// commit before it is what's read, or the file alone if there is none.
#[test]
fn a_damaged_frame_ends_the_log() {
    let (file, mut wal) = files();
    let committed = Database::open_with_wal(&file, &wal)
        .unwrap()
        .wal
        .unwrap()
        .committed_frames;
    wal[WAL_HEADER_SIZE + (committed - 1) * FRAME_SIZE + FRAME_HEADER_SIZE + 100] ^= 0xff;
    let db = Database::open_with_wal(&file, &wal).unwrap();
    let summary = db.wal.as_ref().unwrap();
    assert_eq!(summary.valid_frames, committed - 1);
    assert!(summary.committed_frames < committed);
    if summary.committed_frames == 0 {
        assert_eq!(notes(&db), notes(&Database::open(&file).unwrap()));
    }
}

#[test]
fn a_log_that_is_not_one_is_ignored() {
    let (file, mut wal) = files();
    wal[0] ^= 0xff;
    let db = Database::open_with_wal(&file, &wal).unwrap();
    assert!(db.wal.is_none());
    assert_eq!(db.problems.len(), 1, "{:?}", db.problems);
    assert!(db.problems[0].starts_with("WAL ignored: magic number"));
    assert_eq!(notes(&db), notes(&Database::open(&file).unwrap()));
}

#[test]
fn a_damaged_log_header_is_ignored() {
    let (file, mut wal) = files();
    wal[13] ^= 0x01; // the checkpoint sequence, under the header checksum
    let db = Database::open_with_wal(&file, &wal).unwrap();
    assert!(db.wal.is_none());
    assert_eq!(db.problems, ["WAL ignored: header checksum does not match"]);
}

#[test]
fn a_log_cut_mid_frame_keeps_its_commits() {
    let (file, wal) = files();
    let full = Database::open_with_wal(&file, &wal).unwrap();
    let summary = full.wal.as_ref().unwrap();
    let cut = WAL_HEADER_SIZE + summary.valid_frames * FRAME_SIZE + 100;
    let db = Database::open_with_wal(&file, &wal[..cut]).unwrap();
    assert_eq!(
        db.problems,
        ["WAL: 100 bytes after the last whole frame (a write cut short)"]
    );
    assert_eq!(
        db.wal.as_ref().unwrap().committed_frames,
        summary.committed_frames
    );
    assert_eq!(notes(&db), notes(&full));
}

#[test]
fn an_empty_log_is_no_log() {
    let (file, _) = files();
    let db = Database::open_with_wal(&file, &[]).unwrap();
    assert!(db.wal.is_none() && db.problems.is_empty());
    assert_eq!(notes(&db), notes(&Database::open(&file).unwrap()));
    assert_eq!(notes(&db)[0].values[0], Value::Integer(1));
}

/// `wal` with its magic number and checksums redone for big-endian words,
/// as far as its frames carry the header's salts.
fn big_endian_copy(wal: &[u8]) -> Vec<u8> {
    let mut big = wal.to_vec();
    big[..4].copy_from_slice(&0x377f_0683u32.to_be_bytes());
    let mut sums = checksum((0, 0), &big[..24]);
    put_checksum(&mut big[24..32], sums);
    let salts = big[16..24].to_vec();
    for frame in big[WAL_HEADER_SIZE..].as_chunks_mut::<FRAME_SIZE>().0 {
        if frame[8..16] != salts[..] {
            break;
        }
        sums = checksum(checksum(sums, &frame[..8]), &frame[FRAME_HEADER_SIZE..]);
        put_checksum(&mut frame[16..24], sums);
    }
    big
}

/// The log checksum over big-endian words, written independently of the
/// crate's.
fn checksum((mut s0, mut s1): (u32, u32), bytes: &[u8]) -> (u32, u32) {
    for pair in bytes.as_chunks::<8>().0 {
        let x0 = u32::from_be_bytes(pair[..4].try_into().unwrap());
        let x1 = u32::from_be_bytes(pair[4..].try_into().unwrap());
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
    }
    (s0, s1)
}

fn put_checksum(field: &mut [u8], (s0, s1): (u32, u32)) {
    field[..4].copy_from_slice(&s0.to_be_bytes());
    field[4..].copy_from_slice(&s1.to_be_bytes());
}

/// A checksum-valid test log, made independently of the parser.
fn test_log(frames: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut log = vec![0; WAL_HEADER_SIZE];
    log[..4].copy_from_slice(&0x377f_0683u32.to_be_bytes());
    log[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
    log[8..12].copy_from_slice(&(PAGE_SIZE as u32).to_be_bytes());
    log[16..20].copy_from_slice(&1u32.to_be_bytes());
    log[20..24].copy_from_slice(&2u32.to_be_bytes());
    let mut sums = checksum((0, 0), &log[..24]);
    put_checksum(&mut log[24..32], sums);
    for &(number, commit, page) in frames {
        assert_eq!(page.len(), PAGE_SIZE);
        let mut frame = vec![0; FRAME_HEADER_SIZE];
        frame[..4].copy_from_slice(&number.to_be_bytes());
        frame[4..8].copy_from_slice(&commit.to_be_bytes());
        frame[8..16].copy_from_slice(&log[16..24]);
        sums = checksum(checksum(sums, &frame[..8]), page);
        put_checksum(&mut frame[16..24], sums);
        log.extend(frame);
        log.extend_from_slice(page);
    }
    log
}

#[test]
fn rejected_wal_page_one_does_not_replace_the_file_header() {
    let (file, _) = files();
    let before = Database::open(&file).unwrap();
    let mut page = file[..PAGE_SIZE].to_vec();
    page[16..18].copy_from_slice(&1024u16.to_be_bytes());
    let log = test_log(&[(1, before.page_count, &page)]);
    let db = Database::open_with_wal(&file, &log).unwrap();
    assert!(db.wal.is_none());
    assert_eq!(db.header, before.header);
    assert_eq!(db.schema, before.schema);
    assert_eq!(notes(&db), notes(&before));
    assert!(db.problems.iter().any(|p| p.starts_with("WAL ignored:")));
}

#[test]
fn invalid_wal_page_one_keeps_a_readable_file() {
    let (file, _) = files();
    let before = Database::open(&file).unwrap();
    let page = [0; PAGE_SIZE];
    let log = test_log(&[(1, before.page_count, &page)]);
    let db = Database::open_with_wal(&file, &log).unwrap();
    assert!(db.wal.is_none());
    assert_eq!(db.header, before.header);
    assert_eq!(notes(&db), notes(&before));
    assert!(db.problems.iter().any(|p| p.starts_with("WAL ignored:")));
}

#[test]
fn valid_wal_page_one_can_restore_a_damaged_file_header() {
    let (mut file, _) = files();
    let before = Database::open(&file).unwrap();
    let page = file[..PAGE_SIZE].to_vec();
    let log = test_log(&[(1, before.page_count, &page)]);
    let expected = notes(&before);
    file[..16].fill(0);
    let db = Database::open_with_wal(&file, &log).unwrap();
    assert!(db.wal.is_some());
    assert_eq!(notes(&db), expected);
}

#[test]
fn a_far_wal_page_does_not_allocate_a_huge_image() {
    let (file, _) = files();
    let page = [0; PAGE_SIZE];
    // Only 536 log bytes, but a 32 MiB logical address. Larger numbers must
    // not request terabytes of memory from a small evidence file.
    let log = test_log(&[(65_536, 65_536, &page)]);
    let db = Database::open_with_wal(&file, &log).unwrap();
    let image = db.image();
    assert!(
        image.len() <= 2 * (file.len() + PAGE_SIZE),
        "{} bytes",
        image.len()
    );
    assert!(db.problems.iter().any(|p| p.contains("available pages")));
    assert_eq!(notes(&db), notes(&Database::open(&file).unwrap()));
}

#[test]
fn small_gaps_still_export_pages_at_their_original_offsets() {
    let (file, _) = files();
    let number = (file.len() / PAGE_SIZE) as u32 + 2;
    let page = [0xa5; PAGE_SIZE];
    let log = test_log(&[(number, number, &page)]);
    let db = Database::open_with_wal(&file, &log).unwrap();
    let image = db.image();
    assert_eq!(image.len(), number as usize * PAGE_SIZE);
    assert_eq!(&image[file.len()..file.len() + PAGE_SIZE], &[0; PAGE_SIZE]);
    assert_eq!(&image[image.len() - PAGE_SIZE..], &page);
    assert!(db.problems.is_empty(), "{:?}", db.problems);
}
