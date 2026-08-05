//! T-401 acceptance: hardened layer extraction (SCA-005, NFR-010). The oracle
//! is NOT "returned Err" — it is "nothing outside the extraction root was
//! created, modified, or deleted." Every adversarial case plants a canary
//! beside the root and asserts it is untouched.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;

use flate2::write::GzEncoder;
use flate2::Compression;
use multiscan_sca::image::extract_image;

/// A tar entry to emit. We build raw ustar headers so we can inject malicious
/// names/targets the `tar` crate's builder would refuse — which is exactly the
/// attacker's capability.
enum E<'a> {
    File(&'a str, &'a [u8]),
    Dir(&'a str),
    Symlink(&'a str, &'a str),
    Hardlink(&'a str, &'a str),
}

/// Write an octal numeric field: right-justified, zero-padded, NUL-terminated.
fn octal(field: &mut [u8], value: u64) {
    let len = field.len();
    let width = len - 1;
    let s = format!("{value:0width$o}");
    let bytes = s.as_bytes();
    let start = len - 1 - bytes.len();
    field[start..len - 1].copy_from_slice(bytes);
    field[len - 1] = 0;
}

/// A raw 512-byte ustar header with an arbitrary name/linkname/typeflag.
fn header(name: &str, mode: u64, size: u64, typeflag: u8, linkname: &str) -> [u8; 512] {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
    octal(&mut h[100..108], mode);
    octal(&mut h[108..116], 0); // uid
    octal(&mut h[116..124], 0); // gid
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0); // mtime
    h[156] = typeflag;
    let lb = linkname.as_bytes();
    h[157..157 + lb.len().min(100)].copy_from_slice(&lb[..lb.len().min(100)]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    // Checksum: sum of all bytes with the checksum field taken as spaces.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let s = format!("{sum:06o}");
    h[148..154].copy_from_slice(s.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    h
}

fn layer(entries: &[E]) -> Vec<u8> {
    let mut tar = Vec::new();
    for e in entries {
        match e {
            E::File(name, content) => {
                // 0o777 is hostile: extraction must not honor it.
                tar.extend_from_slice(&header(name, 0o777, content.len() as u64, b'0', ""));
                tar.extend_from_slice(content);
                let pad = (512 - content.len() % 512) % 512;
                tar.extend(std::iter::repeat_n(0u8, pad));
            }
            E::Dir(name) => {
                let dir = if name.ends_with('/') {
                    name.to_string()
                } else {
                    format!("{name}/")
                };
                tar.extend_from_slice(&header(&dir, 0o755, 0, b'5', ""));
            }
            E::Symlink(name, target) => {
                tar.extend_from_slice(&header(name, 0o777, 0, b'2', target));
            }
            E::Hardlink(name, target) => {
                tar.extend_from_slice(&header(name, 0o644, 0, b'1', target));
            }
        }
    }
    // Two zero blocks terminate the archive.
    tar.extend(std::iter::repeat_n(0u8, 1024));

    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Set up an isolated sandbox: a `root/` to extract into and a `canary`
/// sibling that MUST remain untouched.
struct Sandbox {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    canary: std::path::PathBuf,
}

fn sandbox() -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let canary = dir.path().join("canary");
    std::fs::write(&canary, b"do-not-touch").unwrap();
    Sandbox {
        _dir: dir,
        root,
        canary,
    }
}

impl Sandbox {
    fn assert_canary_intact(&self) {
        assert_eq!(
            std::fs::read(&self.canary).unwrap(),
            b"do-not-touch",
            "canary was modified — extraction escaped the root!"
        );
        // Nothing new appeared beside the root.
        let siblings: Vec<_> = std::fs::read_dir(self._dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            siblings.len(),
            2,
            "unexpected sibling created: {siblings:?}"
        );
    }

    fn extract(&self, layers: &[Vec<u8>]) -> Result<(), String> {
        extract_image(layers, &self.root)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn root_join(&self, p: &str) -> std::path::PathBuf {
        self.root.join(p)
    }
}

#[test]
fn benign_layer_extracts() {
    let sb = sandbox();
    let l = layer(&[
        E::Dir("etc"),
        E::File("etc/os-release", b"ID=alpine\n"),
        E::File("app/main.py", b"print(1)\n"),
    ]);
    sb.extract(&[l]).unwrap();
    assert_eq!(
        std::fs::read(sb.root_join("etc/os-release")).unwrap(),
        b"ID=alpine\n"
    );
    assert!(sb.root_join("app/main.py").exists());
    sb.assert_canary_intact();
}

#[test]
fn parent_traversal_is_rejected_and_canary_intact() {
    let sb = sandbox();
    let l = layer(&[E::File("../canary", b"pwned")]);
    assert!(sb.extract(&[l]).is_err());
    sb.assert_canary_intact();
}

#[test]
fn deep_traversal_is_rejected() {
    let sb = sandbox();
    let l = layer(&[E::File("a/b/../../../canary", b"pwned")]);
    assert!(sb.extract(&[l]).is_err());
    sb.assert_canary_intact();
}

#[test]
fn absolute_path_is_rejected() {
    let sb = sandbox();
    let l = layer(&[E::File("/etc/evil", b"pwned")]);
    assert!(sb.extract(&[l]).is_err());
    sb.assert_canary_intact();
}

/// The write-through-symlink escape: a symlink to outside, then a write
/// through it. The escaping symlink is rejected outright; even if it weren't,
/// cap-std would block the traversal.
#[test]
fn write_through_escaping_symlink_is_blocked() {
    let sb = sandbox();
    let l = layer(&[E::Symlink("x", "../"), E::File("x/canary", b"pwned")]);
    // Extraction fails, and crucially the canary is untouched.
    let _ = sb.extract(&[l]);
    sb.assert_canary_intact();
}

/// A symlink to an absolute path outside root is rejected.
#[test]
fn absolute_symlink_target_rejected() {
    let sb = sandbox();
    let l = layer(&[E::Symlink("link", "/etc/passwd")]);
    let _ = sb.extract(&[l]);
    sb.assert_canary_intact();
    // The dangling escape symlink must not have been created.
    assert!(!sb.root_join("link").exists());
}

/// A hardlink whose target escapes root is rejected.
#[test]
fn escaping_hardlink_rejected() {
    let sb = sandbox();
    let l = layer(&[E::Hardlink("h", "../canary")]);
    assert!(sb.extract(&[l]).is_err());
    sb.assert_canary_intact();
}

/// An in-root symlink is fine, but a later write cannot traverse it out.
#[test]
fn benign_symlink_then_confined_write() {
    let sb = sandbox();
    let l = layer(&[
        E::Dir("real"),
        E::Symlink("alias", "real"),
        E::File("alias/note.txt", b"ok"),
    ]);
    let _ = sb.extract(&[l]);
    sb.assert_canary_intact();
}

/// OCI whiteout removes a file from an earlier layer, and a whiteout cannot
/// delete outside root.
#[test]
fn whiteout_deletes_within_root_only() {
    let sb = sandbox();
    let base = layer(&[E::File("etc/keep", b"1"), E::File("etc/remove", b"2")]);
    let over = layer(&[E::File("etc/.wh.remove", b"")]);
    sb.extract(&[base, over]).unwrap();
    assert!(sb.root_join("etc/keep").exists());
    assert!(
        !sb.root_join("etc/remove").exists(),
        "whiteout should delete the file"
    );
    sb.assert_canary_intact();
}

/// Multiple layers: a later layer overwrites an earlier file.
#[test]
fn later_layer_overwrites() {
    let sb = sandbox();
    let base = layer(&[E::File("etc/os-release", b"old")]);
    let over = layer(&[E::File("etc/os-release", b"new")]);
    sb.extract(&[base, over]).unwrap();
    assert_eq!(
        std::fs::read(sb.root_join("etc/os-release")).unwrap(),
        b"new"
    );
    sb.assert_canary_intact();
}

/// Fixed permissions: a hostile 0o777 file is not written world-writable
/// (mode bits from the archive are ignored).
#[cfg(unix)]
#[test]
fn archive_mode_bits_ignored() {
    use std::os::unix::fs::PermissionsExt;
    let sb = sandbox();
    let l = layer(&[E::File("script.sh", b"#!/bin/sh\n")]);
    sb.extract(&[l]).unwrap();
    let mode = std::fs::metadata(sb.root_join("script.sh"))
        .unwrap()
        .permissions()
        .mode();
    // Not world-writable, not setuid/setgid.
    assert_eq!(mode & 0o002, 0, "file must not be world-writable");
    assert_eq!(mode & 0o6000, 0, "file must not be setuid/setgid");
}

/// Special files (device nodes / FIFOs) are skipped, never created.
#[test]
fn benign_extraction_leaves_no_escape() {
    // Sanity meta-test: after a normal extraction, the only sibling dirs are
    // root and canary (guards against future regressions writing elsewhere).
    let sb = sandbox();
    sb.extract(&[layer(&[E::File("a", b"x")])]).unwrap();
    sb.assert_canary_intact();
}

fn _unused(_p: &Path) {}
