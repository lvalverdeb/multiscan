//! OS package-database parsing for container images (spec 7.1). Reads dpkg
//! (Debian/Ubuntu) and apk (Alpine) installed databases — both text stanza
//! formats — plus `os-release` to determine the release-qualified OSV
//! ecosystem. All reads are confined beneath the extracted-image root via
//! cap-std, so a hostile image cannot make us read outside it.
//!
//! rpm's installed database is a binary format (bdb/ndb/sqlite of header
//! blobs); it is detected and reported as an unsupported-DB degradation rather
//! than mis-parsed. rpm *version* comparison is wired (see `version::Scheme`)
//! for when advisory data for an rpm ecosystem is present.

use cap_std::fs::Dir;

/// One installed OS package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsPackage {
    /// Package name.
    pub name: String,
    /// Installed version (dpkg/apk/rpm native form).
    pub version: String,
    /// Architecture, if recorded.
    pub arch: Option<String>,
}

/// The detected image OS, mapped to an OSV ecosystem and purl type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsRelease {
    /// `os-release` ID (e.g. `debian`, `ubuntu`, `alpine`).
    pub id: String,
    /// `os-release` VERSION_ID (e.g. `11`, `22.04`, `3.20`).
    pub version_id: Option<String>,
}

impl OsRelease {
    /// The release-qualified OSV ecosystem (e.g. `Debian:11`, `Alpine:v3.20`),
    /// or `None` if we cannot form one.
    pub fn osv_ecosystem(&self) -> Option<String> {
        let v = self.version_id.as_deref();
        match self.id.as_str() {
            "debian" => v.map(|v| format!("Debian:{}", v.split('.').next().unwrap_or(v))),
            "ubuntu" => v.map(|v| format!("Ubuntu:{v}")),
            "alpine" => v.map(|v| {
                // OSV uses the minor series, e.g. Alpine:v3.20.
                let series: Vec<&str> = v.split('.').take(2).collect();
                format!("Alpine:v{}", series.join("."))
            }),
            // rpm distros. OSV names: "Red Hat" (unqualified), "Rocky Linux:9",
            // "AlmaLinux:9", "Fedora:39".
            "rhel" | "centos" => Some("Red Hat".to_string()),
            "rocky" => v.map(|v| format!("Rocky Linux:{}", v.split('.').next().unwrap_or(v))),
            "almalinux" => v.map(|v| format!("AlmaLinux:{}", v.split('.').next().unwrap_or(v))),
            "fedora" => v.map(|v| format!("Fedora:{v}")),
            _ => None,
        }
    }

    /// The purl type for packages of this OS.
    pub fn purl_type(&self) -> &str {
        match self.id.as_str() {
            "alpine" => "apk",
            "debian" | "ubuntu" => "deb",
            _ => "rpm",
        }
    }

    /// The purl namespace (distro) for packages of this OS.
    pub fn purl_namespace(&self) -> &str {
        &self.id
    }
}

/// Parse `etc/os-release` from the extracted root.
pub fn detect_os(root: &Dir) -> Option<OsRelease> {
    let text = read_confined(root, "etc/os-release")
        .or_else(|| read_confined(root, "usr/lib/os-release"))?;
    let mut id = None;
    let mut version_id = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(unquote(v));
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(unquote(v));
        }
    }
    id.map(|id| OsRelease { id, version_id })
}

/// Read all installed OS packages from whichever database is present.
/// Returns `(packages, unsupported_db)` — the flag is set when an rpm database
/// is present in a format we do not parse (Berkeley DB / ndb), so the caller
/// can degrade to `Partial`.
pub fn read_packages(root: &Dir) -> (Vec<OsPackage>, bool) {
    if let Some(text) = read_confined(root, "var/lib/dpkg/status") {
        return (parse_dpkg_status(&text), false);
    }
    if let Some(text) = read_confined(root, "lib/apk/db/installed") {
        return (parse_apk_installed(&text), false);
    }
    // Modern rpm (RHEL 9+/Fedora): the sqlite rpmdb, whose Packages blobs are
    // raw rpm headers.
    for sqlite_db in [
        "var/lib/rpm/rpmdb.sqlite",
        "usr/lib/sysimage/rpm/rpmdb.sqlite",
    ] {
        if let Some(bytes) = read_confined_bytes(root, sqlite_db) {
            if let Some(packages) = crate::image::rpmdb::read_sqlite_rpmdb(&bytes) {
                return (packages, false);
            }
        }
    }
    // Older rpm (RHEL 7/8): Berkeley DB / ndb — detected but not parsed.
    for rpmdb in ["var/lib/rpm/Packages", "var/lib/rpm/Packages.db"] {
        if dir_has(root, rpmdb) {
            return (Vec::new(), true);
        }
    }
    (Vec::new(), false)
}

/// Parse a dpkg `status` file. Stanzas are separated by blank lines; we take
/// `Package`, `Version`, `Architecture`, and only installed packages
/// (`Status: install ok installed`).
pub fn parse_dpkg_status(text: &str) -> Vec<OsPackage> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut installed = true; // absent Status = assume installed
        for line in stanza.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Status: ") {
                installed = v.contains("installed") && !v.contains("not-installed");
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            if installed {
                out.push(OsPackage {
                    name,
                    version,
                    arch,
                });
            }
        }
    }
    out
}

/// Parse an apk `installed` database. Stanzas separated by blank lines; fields
/// are single letters: `P` name, `V` version, `A` arch.
pub fn parse_apk_installed(text: &str) -> Vec<OsPackage> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        for line in stanza.lines() {
            match line.split_once(':') {
                Some(("P", v)) => name = Some(v.trim().to_string()),
                Some(("V", v)) => version = Some(v.trim().to_string()),
                Some(("A", v)) => arch = Some(v.trim().to_string()),
                _ => {}
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            out.push(OsPackage {
                name,
                version,
                arch,
            });
        }
    }
    out
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').trim_matches('\'').to_string()
}

/// Read a small text file confined beneath `root`; `None` if absent/unreadable.
fn read_confined(root: &Dir, path: &str) -> Option<String> {
    use std::io::Read;
    let mut file = root.open(path).ok()?;
    let mut buf = Vec::new();
    // Cap package DBs at 256 MiB (untrusted input).
    file.by_ref()
        .take(256 * 1024 * 1024)
        .read_to_end(&mut buf)
        .ok()?;
    String::from_utf8(buf).ok()
}

/// Read a (possibly large, binary) file confined beneath `root`; `None` if
/// absent/unreadable. Capped at 512 MiB (an rpmdb can be large but not
/// unbounded — untrusted input).
fn read_confined_bytes(root: &Dir, path: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = root.open(path).ok()?;
    let mut buf = Vec::new();
    file.by_ref()
        .take(512 * 1024 * 1024)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn dir_has(root: &Dir, path: &str) -> bool {
    root.metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_status_parses_installed_only() {
        let text = "Package: bash\nStatus: install ok installed\nVersion: 5.1-2+deb11u1\nArchitecture: amd64\n\nPackage: gone\nStatus: deinstall ok not-installed\nVersion: 1.0\n\nPackage: openssl\nStatus: install ok installed\nVersion: 1.1.1n-0+deb11u3\n";
        let pkgs = parse_dpkg_status(text);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].version, "5.1-2+deb11u1");
        assert!(pkgs.iter().all(|p| p.name != "gone"));
    }

    #[test]
    fn apk_installed_parses() {
        let text = "C:Q1abc\nP:musl\nV:1.2.4-r0\nA:x86_64\n\nP:openssl\nV:3.1.4-r5\nA:x86_64\n";
        let pkgs = parse_apk_installed(text);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[1].version, "3.1.4-r5");
    }

    #[test]
    fn os_release_ecosystems() {
        let debian = OsRelease {
            id: "debian".into(),
            version_id: Some("11".into()),
        };
        assert_eq!(debian.osv_ecosystem().as_deref(), Some("Debian:11"));
        assert_eq!(debian.purl_type(), "deb");

        let alpine = OsRelease {
            id: "alpine".into(),
            version_id: Some("3.20.3".into()),
        };
        assert_eq!(alpine.osv_ecosystem().as_deref(), Some("Alpine:v3.20"));
        assert_eq!(alpine.purl_type(), "apk");
    }
}
