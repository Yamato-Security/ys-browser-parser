"""Writes what dissect.database's ESE reader reads from WebCache databases, as sorted TSV lines.

One line per row, by kind (the first two columns are the file, as given, and the kind):

    container  id, name, directory, secure directories (joined with |), last access, last scavenge
    visit      table, id, account, url, time (AccessedTime)
    download   container, id, url, target path, current path, start, size, referrer,
               MIME type, publisher, AccessedTime
    entry      container, its name, id, url, account, file name, file path, file size, type,
               flags, access count, created, modified, accessed, expires, synced, sync count,
               request headers' length, response headers' first line and length, redirect URL
    cookie     table, its PartitionsEx directory, id, host, path, name, value, expires,
               last modified, flags

Times are FILETIMEs written as UTC, `YYYY-MM-DDTHH:MM:SS.fffffffZ`; zero is empty, as are
missing values. Backslashes, tabs, carriage returns and line feeds in text are written as
\\\\, \\t, \\r and \\n. Records flagged deleted on their page (not yet cleaned up) are left
out, as ESE leaves them out.

Downloads are decoded here independently of the crate, from what their `ResponseHeaders`
records were seen to hold: the start (a FILETIME at 0x24) and size (a u64 at 0x48) when the
header (its size the record's first u32) is at least 0x50 bytes and fits the record, and the NUL-terminated
UTF-16 strings that end the record: the target path, the URL, the path written while
downloading (when it is a path), then the MIME type, the referrer and a publisher.

    pip install dissect.database
    python3 -I webcache_tsv.py <WebCacheV01.dat[.gz]> ... | sort | gzip -9n > webcache.tsv.gz
"""

import datetime
import gzip
import io
import os
import re
import struct
import sys

from dissect.database.ese import ESE

EPOCH = datetime.datetime(1601, 1, 1)
TABLELESS = {"MicrosoftEdge_DNTException", "MicrosoftEdge_EmieSiteList", "MicrosoftEdge_EmieUserList"}


def escape(value):
    if value is None:
        return ""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def filetime(value):
    if not value or value <= 0:
        return None
    if value == 0x7FFFFFFFFFFFFFFF:
        return None
    time = EPOCH + datetime.timedelta(microseconds=value // 10)
    return time.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % (value % 10_000_000)


def text(value):
    return value if isinstance(value, str) and value else None


def live(records):
    for record in records:
        tag = getattr(getattr(record, "_node", None), "tag", None)
        if tag is not None and "Deleted" in str(getattr(tag, "flags", "")):
            continue
        yield record


def split_url(raw):
    if "@" not in raw:
        return None, raw
    head, url = raw.split("@", 1)
    if ": " in head:
        prefix, user = head.rsplit(": ", 1)
        if "/" not in prefix and "/" not in user:
            return user, url
    return None, raw


def headers(data):
    if not data:
        return None
    data = data.rstrip(b"\x00")
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value or any(
        (ord(c) < 0x20 and c not in "\r\n\t") or 0x7F <= ord(c) < 0xA0 for c in value
    ):
        return None
    return value


def trailing_strings(data):
    if len(data) % 2:
        data = data[1:]
    units = [struct.unpack_from("<H", data, i)[0] for i in range(0, len(data), 2)]
    if not units or units[-1] != 0:
        return []
    rest = units[:-1]
    strings = []
    while True:
        start = len(rest) - rest[::-1].index(0) if 0 in rest else 0
        try:
            value = b"".join(struct.pack("<H", u) for u in rest[start:]).decode("utf-16le")
        except UnicodeDecodeError:
            break
        if not value or any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in value):
            break
        strings.append(value)
        if start == 0:
            break
        rest = rest[: start - 1]
    return strings[::-1]


def is_path(value):
    return value.startswith(("\\\\", "//")) or (
        len(value) > 2 and value[0].isascii() and value[0].isalpha() and value[1:3] in (":\\", ":/")
    )


def is_uri(value):
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:.+$", value)) and not is_path(value)


def line(*values):
    print("\t".join(escape(v) for v in values))


def read(name, data):
    db = ESE(io.BytesIO(data))
    tables = {t.name.lower(): t.name for t in db.tables()}
    for row in live(db.table("Containers").records()):
        cid, cname, directory = row.get("ContainerId"), row.get("Name"), text(row.get("Directory"))
        names = row.get("SecureDirectories") or ""
        secure = [names[i : i + 8] for i in range(0, len(names), 8)]
        line(name, "container", cid, cname, directory, "|".join(secure),
             filetime(row.get("LastAccessTime")), filetime(row.get("LastScavengeTime")))
        table = tables.get(f"container_{cid}")
        if not table:
            continue
        history = cname == "History" or cname.startswith("MSHist")
        for entry in live(db.table(table).records()):
            get = entry.get
            url = get("Url") or ""
            if history:
                if not url:
                    continue
                user, url = split_url(url)
                line(name, "visit", table, get("EntryId"), user, url, filetime(get("AccessedTime")))
            elif cname == "iedownload":
                record = get("ResponseHeaders") or b""
                header = struct.unpack_from("<I", record, 0)[0] if len(record) >= 4 else 0
                numbers = 0x50 <= header <= len(record)
                accessed = filetime(get("AccessedTime"))
                start = filetime(struct.unpack_from("<Q", record, 0x24)[0]) if numbers else None
                size = struct.unpack_from("<Q", record, 0x48)[0] if numbers else None
                strings = trailing_strings(record[header:]) if numbers else []
                target = current = mime = referrer = publisher = None
                if len(strings) < 2 or not is_path(strings[-1]) or not is_uri(strings[-2]):
                    target, source = "", url
                else:
                    target, source = strings.pop(), strings.pop()
                    if strings and is_path(strings[-1]):
                        current = strings.pop()
                    for value in reversed(strings):
                        if re.fullmatch(r"[A-Za-z0-9+.\-_]+/[A-Za-z0-9+.\-_]+", value):
                            mime = mime or value
                        elif "://" in value:
                            referrer = referrer or value
                        else:
                            publisher = publisher or value
                line(name, "download", cid, get("EntryId"), source, target, current,
                     start or accessed, size, referrer, mime, publisher, accessed)
            else:
                file_name = text(get("Filename"))
                file_path = None
                if file_name and directory:
                    index, base = get("SecureDirectory"), directory.rstrip("\\")
                    if not index:
                        file_path = f"{base}\\{file_name}"
                    elif 1 <= index <= len(secure):
                        file_path = f"{base}\\{secure[index - 1]}\\{file_name}"
                user = None
                if url.startswith("Cookie:") and "@" in url[7:]:
                    account = url[7:].split("@", 1)[0]
                    user = account if account and "/" not in account else None
                response = get("ResponseHeaders")
                response = headers(response) if response and response.startswith(b"HTTP/") else None
                request = headers(get("RequestHeaders"))
                line(name, "entry", cid, cname, get("EntryId"), url, user, file_name, file_path,
                     get("FileSize"), get("Type"), get("Flags"), get("AccessCount"),
                     filetime(get("CreationTime")), filetime(get("ModifiedTime")),
                     filetime(get("AccessedTime")), filetime(get("ExpiryTime")),
                     filetime(get("SyncTime")), get("SyncCount"),
                     len(request) if request else None,
                     response.splitlines()[0] if response else None,
                     len(response) if response else None, text(get("RedirectUrl")))
    directories = {}
    if "partitionsex" in tables:
        for row in live(db.table(tables["partitionsex"]).records()):
            if row.get("TableId") is not None and text(row.get("Directory")):
                directories[row.get("TableId")] = row.get("Directory")
    for lower, table in tables.items():
        if not lower.startswith("cookieentryex_"):
            continue
        try:
            number = int(table[len("CookieEntryEx_"):])
        except ValueError:
            number = None
        for row in live(db.table(table).records()):
            get = row.get

            def cookie(value):
                if isinstance(value, bytes):
                    return value.rstrip(b"\x00").decode("utf-8", "replace")
                return value.rstrip("\x00") if isinstance(value, str) else ""

            domain = text(get("RDomain"))
            line(name, "cookie", table, directories.get(number), get("EntryId"),
                 ".".join(reversed(domain.split("."))) if domain else "", get("Path") or "",
                 cookie(get("Name")), cookie(get("Value")), filetime(get("Expires")),
                 filetime(get("LastModified")), get("Flags"))


for path in sys.argv[1:]:
    with open(path, "rb") as file:
        data = file.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    read(os.path.basename(path), data)
