#!/bin/sh
# Recreates the form history databases, written by the sqlite3 shell from synthetic SQL
# (documentation domains, RFC 2606). The tables are Firefox 140's, as its
# toolkit/components/satchel creates them (schema version 5).
#
# Removal rows here are synthesized: normal Firefox builds populate them only on Android.
#
# - formhistory.sqlite: four entries (one with a fraction of a millisecond in
#   its times, two with sources: the search bar's engine names), and one entry
#   deleted with secure_delete off, so that its record stays in the page's
#   free space, with its removal in moz_deleted_formhistory.
# - wal/formhistory.sqlite, wal/formhistory.sqlite-wal: write-ahead log mode,
#   as Firefox keeps it. The entries are checkpointed into the file; then, in
#   the log only and with secure_delete on, as Firefox deletes: one entry is
#   removed (and its removal recorded), one is used again, and a new one is
#   added. Both files are copied while the connection holds them, before any
#   checkpoint, so the file still holds the removed entry's page as it was.
# - old/formhistory.sqlite: the tables before sources (schema version 4):
#   two entries and a removal.
#
#   sudo apt-get install sqlite3
#   sh tests/fixtures/formhistory/gen.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir -p "$here/wal" "$here/old"

# 2026-09-01 08:00:00 UTC in microseconds (PRTime).
t0=1788249600000000

tables="
CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
CREATE TABLE moz_deleted_formhistory (id INTEGER PRIMARY KEY, timeDeleted INTEGER, guid TEXT);
CREATE TABLE moz_sources (id INTEGER PRIMARY KEY, source TEXT NOT NULL);
CREATE TABLE moz_history_to_sources (history_id INTEGER, source_id INTEGER, PRIMARY KEY (history_id, source_id), FOREIGN KEY (history_id) REFERENCES moz_formhistory(id) ON DELETE CASCADE, FOREIGN KEY (source_id) REFERENCES moz_sources(id) ON DELETE CASCADE) WITHOUT ROWID;
CREATE INDEX moz_formhistory_index ON moz_formhistory(fieldname);
CREATE INDEX moz_formhistory_lastused_index ON moz_formhistory(lastUsed);
CREATE INDEX moz_formhistory_guid_index ON moz_formhistory(guid);
PRAGMA user_version = 5;"

entries="
INSERT INTO moz_formhistory VALUES
 (1,'email','alice@example.com',2,$t0+123456,$t0+3600000789,'GuIdEmAiL0000001'),
 (2,'searchbar-history','quarterly report',3,$t0+60000000,$t0+7200000000,'GuIdSeArCh000002'),
 (3,'searchbar-history','example.org login',1,$t0+90000000,$t0+90000000,'GuIdSeArCh000003'),
 (4,'city','Springfield',1,$t0+120000000,$t0+120000000,'GuIdCiTy00000004');
INSERT INTO moz_sources VALUES (1,'Example Search'),(2,'Example Encyclopedia');
INSERT INTO moz_history_to_sources VALUES (2,1),(2,2),(3,1);"

# --- formhistory.sqlite ------------------------------------------------------
sqlite3 formhistory.sqlite <<SQL
PRAGMA secure_delete = OFF;
$tables
$entries
INSERT INTO moz_formhistory VALUES (5,'username','old-account-7',4,$t0+30000000,$t0+86400000000,'GuIdUsErNaMe0005');
DELETE FROM moz_formhistory WHERE id = 5;
INSERT INTO moz_deleted_formhistory (timeDeleted, guid) VALUES ($t0+90000000000,'GuIdUsErNaMe0005');
SQL
cp formhistory.sqlite "$here/formhistory.sqlite"

# --- wal/formhistory.sqlite, wal/formhistory.sqlite-wal ------------------------
mkdir wal
sqlite3 wal/formhistory.sqlite <<SQL
PRAGMA journal_mode = WAL;
PRAGMA wal_autocheckpoint = 0;
$tables
$entries
PRAGMA wal_checkpoint(TRUNCATE);
PRAGMA secure_delete = ON;
DELETE FROM moz_formhistory WHERE id = 4;
INSERT INTO moz_deleted_formhistory (timeDeleted, guid) VALUES ($t0+180000000,'GuIdCiTy00000004');
UPDATE moz_formhistory SET timesUsed = 3, lastUsed = $t0+240000000 WHERE id = 1;
INSERT INTO moz_formhistory VALUES (6,'phone','+1-555-0100',1,$t0+300000000,$t0+300000000,'GuIdPhOnE0000006');
.shell cp wal/formhistory.sqlite "$here/wal/formhistory.sqlite" && cp wal/formhistory.sqlite-wal "$here/wal/formhistory.sqlite-wal"
SQL

# --- old/formhistory.sqlite --------------------------------------------------
mkdir old
sqlite3 old/formhistory.sqlite <<SQL
CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, fieldname TEXT NOT NULL, value TEXT NOT NULL, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);
CREATE TABLE moz_deleted_formhistory (id INTEGER PRIMARY KEY, timeDeleted INTEGER, guid TEXT);
CREATE INDEX moz_formhistory_index ON moz_formhistory(fieldname);
CREATE INDEX moz_formhistory_lastused_index ON moz_formhistory(lastUsed);
CREATE INDEX moz_formhistory_guid_index ON moz_formhistory(guid);
PRAGMA user_version = 4;
INSERT INTO moz_formhistory VALUES
 (1,'q','example.net weather',2,$t0,$t0+600000000,'GuIdOlD000000001'),
 (2,'email','bob@example.net',1,$t0+60000000,$t0+60000000,'GuIdOlD000000002');
INSERT INTO moz_deleted_formhistory (timeDeleted, guid) VALUES ($t0+30000000,'GuIdOlD000000003');
SQL
cp old/formhistory.sqlite "$here/old/formhistory.sqlite"

# Repeated removals/re-entry, an edited live GUID and an in-place GUID rename.
# Tombstones are explicitly synthesized (normally populated only on Android).
mkdir lifecycle
mkdir -p "$here/lifecycle"
sqlite3 lifecycle/formhistory.sqlite <<SQL
PRAGMA journal_mode = WAL;
PRAGMA wal_autocheckpoint = 0;
$tables
INSERT INTO moz_formhistory VALUES
 (1,'searchbar-history','incident response',1,$t0,$t0+1000000,'CycleGuidA000001'),
 (2,'email','before@example.test',1,$t0,$t0+1000000,'StableGuid000001'),
 (3,'q','rename-only',1,$t0,$t0+1000000,'RenameGuid000001'),
 (6,'legacy-guid','unchanged',1,$t0,$t0+1000000,NULL);
PRAGMA wal_checkpoint(TRUNCATE);
PRAGMA secure_delete = ON;
BEGIN;
DELETE FROM moz_formhistory WHERE id = 1;
INSERT INTO moz_deleted_formhistory (timeDeleted,guid) VALUES ($t0+30000000,'CycleGuidA000001');
INSERT INTO moz_formhistory VALUES (4,'searchbar-history','incident response',1,$t0+30000000,$t0+40000000,'CycleGuidB000002');
COMMIT;
BEGIN;
DELETE FROM moz_formhistory WHERE id = 4;
INSERT INTO moz_deleted_formhistory (timeDeleted,guid) VALUES ($t0+50000000,'CycleGuidB000002');
INSERT INTO moz_formhistory VALUES (5,'searchbar-history','incident response',1,$t0+50000000,$t0+60000000,'CycleGuidC000003');
UPDATE moz_formhistory SET value='after@example.test', timesUsed=2, lastUsed=$t0+60000000 WHERE id=2;
UPDATE moz_formhistory SET guid='RenamedGuid00002' WHERE id=3;
UPDATE moz_formhistory SET guid='KnownGuid0000006' WHERE id=6;
COMMIT;
.shell cp lifecycle/formhistory.sqlite "$here/lifecycle/formhistory.sqlite" && cp lifecycle/formhistory.sqlite-wal "$here/lifecycle/formhistory.sqlite-wal"
SQL
