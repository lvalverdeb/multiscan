//! RPM database parsing for the modern SQLite format (spec 7.1). The
//! `rpmdb.sqlite` `Packages` table stores each installed package as a raw RPM
//! *header* blob; we read the table with rusqlite and parse the header
//! ourselves (the `rpm` crate does not expose header-blob parsing).
//!
//! The header is untrusted binary from an image, so parsing is fully bounded:
//! every offset and length is checked, entry/data sizes are capped, and a
//! malformed blob yields `None` rather than a panic (cf. SCA-005 discipline).

use super::ospkg::OsPackage;

/// RPM header magic (`8e ad e8 01`), present when the blob is a
/// "header with magic"; rpmdb blobs are usually the magic-less "import" form.
const HEADER_MAGIC: [u8; 4] = [0x8e, 0xad, 0xe8, 0x01];

/// Defensive caps.
const MAX_INDEX_ENTRIES: u32 = 100_000;
const MAX_DATA_LEN: u32 = 64 * 1024 * 1024;

// RPM tag numbers we care about.
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_ARCH: u32 = 1022;

// RPM data types.
const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;

/// Read all packages from a SQLite rpmdb given its raw file bytes. Writes the
/// bytes to a temp file (the confined read already happened) and queries the
/// `Packages` table. Returns `None` if the file is not a usable sqlite rpmdb.
pub fn read_sqlite_rpmdb(bytes: &[u8]) -> Option<Vec<OsPackage>> {
    // SQLite files start with "SQLite format 3\0".
    if !bytes.starts_with(b"SQLite format 3\0") {
        return None;
    }
    // rusqlite opens by path; write the confined bytes to a private temp file.
    let tmp = tempfile::NamedTempFile::new().ok()?;
    std::fs::write(tmp.path(), bytes).ok()?;
    let conn = rusqlite::Connection::open_with_flags(
        tmp.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .ok()?;

    let mut stmt = conn.prepare("SELECT blob FROM Packages").ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)).ok()?;

    let mut packages = Vec::new();
    for row in rows.flatten() {
        if let Some(pkg) = parse_header(&row) {
            packages.push(pkg);
        }
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages.dedup();
    Some(packages)
}

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a single RPM header blob into an `OsPackage`. Bounded and total.
pub fn parse_header(blob: &[u8]) -> Option<OsPackage> {
    // The blob may start with the 8-byte magic+reserved; skip it if present.
    let start = if blob.len() >= 8 && blob[..4] == HEADER_MAGIC {
        8
    } else {
        0
    };

    let nindex = be_u32(blob, start)?;
    let datalen = be_u32(blob, start + 4)?;
    if nindex == 0 || nindex > MAX_INDEX_ENTRIES || datalen > MAX_DATA_LEN {
        return None;
    }

    let index_start = start + 8;
    let index_bytes = (nindex as usize).checked_mul(16)?;
    let data_start = index_start.checked_add(index_bytes)?;
    let data_end = data_start.checked_add(datalen as usize)?;
    if data_end > blob.len() {
        return None; // truncated / malformed
    }
    let data = &blob[data_start..data_end];

    let mut name = None;
    let mut version = None;
    let mut release = None;
    let mut epoch = None;
    let mut arch = None;

    for i in 0..nindex as usize {
        let entry = index_start + i * 16;
        let tag = be_u32(blob, entry)?;
        let ty = be_u32(blob, entry + 4)?;
        let offset = be_u32(blob, entry + 8)? as usize;
        match tag {
            RPMTAG_NAME if ty == TYPE_STRING => name = read_string(data, offset),
            RPMTAG_VERSION if ty == TYPE_STRING => version = read_string(data, offset),
            RPMTAG_RELEASE if ty == TYPE_STRING => release = read_string(data, offset),
            RPMTAG_ARCH if ty == TYPE_STRING => arch = read_string(data, offset),
            RPMTAG_EPOCH if ty == TYPE_INT32 => {
                epoch = data
                    .get(offset..offset + 4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            }
            _ => {}
        }
    }

    let name = name?;
    let version = version?;
    // Compose the EVR the version matcher expects: [epoch:]version-release.
    let mut evr = String::new();
    if let Some(e) = epoch {
        evr.push_str(&format!("{e}:"));
    }
    evr.push_str(&version);
    if let Some(rel) = &release {
        evr.push('-');
        evr.push_str(rel);
    }
    Some(OsPackage {
        name,
        version: evr,
        arch,
    })
}

/// Read a NUL-terminated string from the data store at `offset`.
fn read_string(data: &[u8], offset: usize) -> Option<String> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal magic-less RPM header with NAME/VERSION/RELEASE/EPOCH.
    fn header(name: &str, version: &str, release: &str, epoch: Option<u32>) -> Vec<u8> {
        // Data store: lay out strings and the epoch int.
        let mut data = Vec::new();
        let mut entries: Vec<(u32, u32, u32)> = Vec::new(); // (tag, type, offset)

        let put_str = |s: &str, data: &mut Vec<u8>| -> u32 {
            let off = data.len() as u32;
            data.extend_from_slice(s.as_bytes());
            data.push(0);
            off
        };
        entries.push((RPMTAG_NAME, TYPE_STRING, put_str(name, &mut data)));
        entries.push((RPMTAG_VERSION, TYPE_STRING, put_str(version, &mut data)));
        entries.push((RPMTAG_RELEASE, TYPE_STRING, put_str(release, &mut data)));
        entries.push((RPMTAG_ARCH, TYPE_STRING, put_str("x86_64", &mut data)));
        if let Some(e) = epoch {
            let off = data.len() as u32;
            data.extend_from_slice(&e.to_be_bytes());
            entries.push((RPMTAG_EPOCH, TYPE_INT32, off));
        }

        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        for (tag, ty, offset) in &entries {
            out.extend_from_slice(&tag.to_be_bytes());
            out.extend_from_slice(&ty.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes()); // count
        }
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn parses_evr_without_epoch() {
        let blob = header("openssl", "1.1.1k", "7.el8", None);
        let pkg = parse_header(&blob).unwrap();
        assert_eq!(pkg.name, "openssl");
        assert_eq!(pkg.version, "1.1.1k-7.el8");
        assert_eq!(pkg.arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn parses_evr_with_epoch() {
        let blob = header("bash", "5.1.8", "4.el9", Some(1));
        let pkg = parse_header(&blob).unwrap();
        assert_eq!(pkg.version, "1:5.1.8-4.el9");
    }

    #[test]
    fn magic_prefixed_header_parsed() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&HEADER_MAGIC);
        blob.extend_from_slice(&[0, 0, 0, 0]); // reserved
        blob.extend_from_slice(&header("zlib", "1.2.11", "1.el8", None));
        let pkg = parse_header(&blob).unwrap();
        assert_eq!(pkg.name, "zlib");
    }

    #[test]
    fn reads_a_real_sqlite_rpmdb() {
        // Build a sqlite rpmdb with a Packages(blob) table and one header.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = rusqlite::Connection::open(tmp.path()).unwrap();
            conn.execute(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)",
                [],
            )
            .unwrap();
            let blob = header("openssl", "3.0.7", "18.el9", Some(1));
            conn.execute("INSERT INTO Packages (blob) VALUES (?1)", [&blob])
                .unwrap();
        }
        let bytes = std::fs::read(tmp.path()).unwrap();
        let packages = read_sqlite_rpmdb(&bytes).expect("valid sqlite rpmdb");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "openssl");
        assert_eq!(packages[0].version, "1:3.0.7-18.el9");
    }

    #[test]
    fn non_sqlite_bytes_rejected() {
        assert!(read_sqlite_rpmdb(b"not a database").is_none());
    }

    #[test]
    fn malformed_blobs_return_none_not_panic() {
        assert!(parse_header(&[]).is_none());
        assert!(parse_header(&[0xff; 4]).is_none());
        // nindex claims many entries but the blob is tiny.
        let mut b = Vec::new();
        b.extend_from_slice(&9999u32.to_be_bytes());
        b.extend_from_slice(&10u32.to_be_bytes());
        assert!(parse_header(&b).is_none());
        // datalen over the cap.
        let mut b2 = Vec::new();
        b2.extend_from_slice(&1u32.to_be_bytes());
        b2.extend_from_slice(&(MAX_DATA_LEN + 1).to_be_bytes());
        assert!(parse_header(&b2).is_none());
    }
}
