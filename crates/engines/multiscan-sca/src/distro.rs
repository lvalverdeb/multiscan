//! Distro identity normalization (ADR 0022).
//!
//! OSV names a distro release one way and `os-release` names it another, and
//! neither is a substring of the other: OSV says `Ubuntu:22.04:LTS` where
//! `os-release` says `ID=ubuntu VERSION_ID=22.04`, and OSV says
//! `Red Hat:enterprise_linux:8::appstream` where `os-release` says `ID=rhel
//! VERSION_ID=8.9`. Both sides are normalized to a [`DistroKey`] and compared
//! as a value, so the comparison lives in exactly one place instead of being
//! spread across prefix tests in the matcher.
//!
//! Deliberate non-matches: Ubuntu Pro is its own [`Distro`] and never matches
//! a plain release (its fixes require a subscription the user may not have —
//! ADR 0022 §6), and Red Hat's layered products (`openshift`,
//! `ansible_automation_platform`, …) share the `Red Hat` bucket but describe
//! no OS package inventory, so they normalize to nothing.

/// A distro, independent of how OSV or `os-release` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Distro {
    Debian,
    Ubuntu,
    /// Ubuntu Pro/ESM — deliberately distinct from [`Distro::Ubuntu`].
    UbuntuPro,
    Alpine,
    Rhel,
    Rocky,
    AlmaLinux,
    OpenSuseLeap,
    OpenSuseLeapMicro,
    OpenSuseTumbleweed,
    Sles,
    Wolfi,
    Chainguard,
    AzureLinux,
    OpenEuler,
    Mageia,
}

impl Distro {
    /// The OSV bucket this distro's advisories are mirrored in — the base
    /// ecosystem name, which is also the snapshot file stem (ADR 0022 §2).
    pub(crate) fn bucket(self) -> &'static str {
        match self {
            Distro::Debian => "Debian",
            Distro::Ubuntu | Distro::UbuntuPro => "Ubuntu",
            Distro::Alpine => "Alpine",
            Distro::Rhel => "Red Hat",
            Distro::Rocky => "Rocky Linux",
            Distro::AlmaLinux => "AlmaLinux",
            Distro::OpenSuseLeap | Distro::OpenSuseLeapMicro | Distro::OpenSuseTumbleweed => {
                "openSUSE"
            }
            Distro::Sles => "SUSE",
            Distro::Wolfi => "Wolfi",
            Distro::Chainguard => "Chainguard",
            Distro::AzureLinux => "Azure Linux",
            Distro::OpenEuler => "openEuler",
            Distro::Mageia => "Mageia",
        }
    }

    /// Human label, for finding locations and evidence text.
    fn label(self) -> &'static str {
        match self {
            Distro::Debian => "Debian",
            Distro::Ubuntu => "Ubuntu",
            Distro::UbuntuPro => "Ubuntu Pro",
            Distro::Alpine => "Alpine",
            Distro::Rhel => "Red Hat Enterprise Linux",
            Distro::Rocky => "Rocky Linux",
            Distro::AlmaLinux => "AlmaLinux",
            Distro::OpenSuseLeap => "openSUSE Leap",
            Distro::OpenSuseLeapMicro => "openSUSE Leap Micro",
            Distro::OpenSuseTumbleweed => "openSUSE Tumbleweed",
            Distro::Sles => "SUSE Linux Enterprise Server",
            Distro::Wolfi => "Wolfi",
            Distro::Chainguard => "Chainguard",
            Distro::AzureLinux => "Azure Linux",
            Distro::OpenEuler => "openEuler",
            Distro::Mageia => "Mageia",
        }
    }
}

/// Every OSV bucket that holds distro advisories (ADR 0022 §1). Ordered as
/// the default mirror set is written; `DET-001` does not apply (this never
/// reaches output unsorted), but keeping one list avoids drift between the
/// feed layer and the matcher.
pub(crate) const DISTRO_BUCKETS: &[&str] = &[
    "Debian",
    "Ubuntu",
    "Alpine",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
    "openSUSE",
    "SUSE",
    "Chainguard",
    "Wolfi",
    "Azure Linux",
    "openEuler",
    "Mageia",
];

/// A distro release, normalized. `release` is empty for rolling or
/// unversioned distros (Tumbleweed, Wolfi, Chainguard).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DistroKey {
    pub(crate) distro: Distro,
    pub(crate) release: String,
}

impl DistroKey {
    fn new(distro: Distro, release: impl Into<String>) -> Self {
        Self {
            distro,
            release: release.into(),
        }
    }

    /// Display form for finding locations, e.g. `Debian 12`, `Wolfi`.
    pub(crate) fn display(&self) -> String {
        if self.release.is_empty() {
            self.distro.label().to_string()
        } else {
            format!("{} {}", self.distro.label(), self.release)
        }
    }

    /// The OSV bucket whose advisories can match this release.
    pub(crate) fn bucket(&self) -> &'static str {
        self.distro.bucket()
    }
}

/// Normalize an OSV `package.ecosystem` string. `None` when the string names
/// no OS release we can resolve a package inventory against — a lockfile
/// ecosystem, a Red Hat layered product, or an unrecognized distro.
pub(crate) fn from_osv_ecosystem(ecosystem: &str) -> Option<DistroKey> {
    let (name, rest) = match ecosystem.split_once(':') {
        Some((name, rest)) => (name.trim(), rest.trim()),
        // Unversioned distro ecosystems carry no release at all.
        None => {
            return match ecosystem.trim() {
                "Wolfi" => Some(DistroKey::new(Distro::Wolfi, "")),
                "Chainguard" => Some(DistroKey::new(Distro::Chainguard, "")),
                _ => None,
            }
        }
    };
    match name {
        "Debian" => Some(DistroKey::new(Distro::Debian, major(rest))),
        // `Ubuntu:22.04:LTS`, `Ubuntu:23.10`, `Ubuntu:Pro:22.04:LTS`.
        "Ubuntu" => match rest.strip_prefix("Pro:") {
            Some(pro) => Some(DistroKey::new(Distro::UbuntuPro, ubuntu_release(pro))),
            None => Some(DistroKey::new(Distro::Ubuntu, ubuntu_release(rest))),
        },
        // `Alpine:v3.20` — the `v` is OSV's, not apk's.
        "Alpine" => Some(DistroKey::new(
            Distro::Alpine,
            series(rest.trim_start_matches('v')),
        )),
        // `Red Hat:enterprise_linux:8::appstream`. Anything else under the
        // Red Hat bucket is a layered product, not an OS release.
        "Red Hat" => rest
            .strip_prefix("enterprise_linux:")
            .map(|v| DistroKey::new(Distro::Rhel, major(v.split("::").next().unwrap_or(v)))),
        "Rocky Linux" => Some(DistroKey::new(Distro::Rocky, major(rest))),
        "AlmaLinux" => Some(DistroKey::new(Distro::AlmaLinux, major(rest))),
        "Mageia" => Some(DistroKey::new(Distro::Mageia, major(rest))),
        "Azure Linux" => Some(DistroKey::new(Distro::AzureLinux, major(rest))),
        // `openEuler:24.03-LTS`, `openEuler:22.03-LTS-SP3`.
        "openEuler" => Some(DistroKey::new(
            Distro::OpenEuler,
            rest.split('-').next().unwrap_or(rest).trim().to_string(),
        )),
        // `openSUSE:Tumbleweed`, `openSUSE:Leap 15.6`,
        // `openSUSE:Leap 15.6 NonFree`, `openSUSE:Leap Micro 5.5`.
        "openSUSE" => {
            if rest.eq_ignore_ascii_case("Tumbleweed") {
                Some(DistroKey::new(Distro::OpenSuseTumbleweed, ""))
            } else if let Some(v) = rest.strip_prefix("Leap Micro ") {
                Some(DistroKey::new(Distro::OpenSuseLeapMicro, series(v)))
            } else {
                rest.strip_prefix("Leap ")
                    .map(|v| DistroKey::new(Distro::OpenSuseLeap, series(v)))
            }
        }
        // `SUSE:Linux Enterprise Server 15 SP4`. The other SUSE products in
        // this bucket (Enterprise Storage, Desktop, HA Extension, …) are not
        // a base OS inventory.
        "SUSE" => rest
            .strip_prefix("Linux Enterprise Server ")
            .map(|v| DistroKey::new(Distro::Sles, sles_release(v))),
        _ => None,
    }
}

/// Normalize an `os-release` `ID` and `VERSION_ID`. `None` when the distro is
/// unknown to us, or known but unresolvable — Debian sid publishes no
/// `VERSION_ID`, and OSV has no Fedora bucket at all (ADR 0022 §9).
pub(crate) fn from_os_release(id: &str, version_id: Option<&str>) -> Option<DistroKey> {
    let id = id.trim().to_ascii_lowercase();
    let version = version_id.map(str::trim).filter(|v| !v.is_empty());
    // Rolling and unversioned distros resolve without a VERSION_ID.
    match id.as_str() {
        "opensuse-tumbleweed" => return Some(DistroKey::new(Distro::OpenSuseTumbleweed, "")),
        "wolfi" => return Some(DistroKey::new(Distro::Wolfi, "")),
        "chainguard" => return Some(DistroKey::new(Distro::Chainguard, "")),
        _ => {}
    }
    let version = version?;
    match id.as_str() {
        "debian" => Some(DistroKey::new(Distro::Debian, major(version))),
        "ubuntu" => Some(DistroKey::new(Distro::Ubuntu, ubuntu_release(version))),
        "alpine" => Some(DistroKey::new(Distro::Alpine, series(version))),
        // CentOS Linux tracked RHEL point-for-point; CentOS Stream leads it,
        // so a Stream image can report a fix that has not shipped for it yet.
        // Reporting against the RHEL release is the conservative direction.
        "rhel" | "centos" => Some(DistroKey::new(Distro::Rhel, major(version))),
        "rocky" => Some(DistroKey::new(Distro::Rocky, major(version))),
        "almalinux" => Some(DistroKey::new(Distro::AlmaLinux, major(version))),
        "mageia" => Some(DistroKey::new(Distro::Mageia, major(version))),
        // CBL-Mariner 2 is Azure Linux 2; the rename happened at 3.
        "azurelinux" | "mariner" => Some(DistroKey::new(Distro::AzureLinux, major(version))),
        "openeuler" => Some(DistroKey::new(
            Distro::OpenEuler,
            version
                .split([' ', '-'])
                .next()
                .unwrap_or(version)
                .to_string(),
        )),
        "opensuse-leap" => Some(DistroKey::new(Distro::OpenSuseLeap, series(version))),
        "opensuse-leap-micro" | "suse-microos" => {
            Some(DistroKey::new(Distro::OpenSuseLeapMicro, series(version)))
        }
        "sles" | "sles_sap" => Some(DistroKey::new(Distro::Sles, series(version))),
        _ => None,
    }
}

/// Leading numeric component: `12.5` → `12`, `8` → `8`.
fn major(v: &str) -> String {
    v.trim().split('.').next().unwrap_or(v).trim().to_string()
}

/// Leading two numeric components: `3.20.3` → `3.20`, `15` → `15`. Anything
/// after whitespace is a repo or edition qualifier, not part of the release —
/// `openSUSE:Leap 15.6 NonFree` is Leap 15.6.
fn series(v: &str) -> String {
    let v = v.split_whitespace().next().unwrap_or("");
    let parts: Vec<&str> = v.split('.').take(2).collect();
    parts.join(".")
}

/// `22.04:LTS` and `22.04` alike → `22.04`.
fn ubuntu_release(v: &str) -> String {
    v.trim()
        .split(':')
        .next()
        .unwrap_or(v)
        .trim()
        .to_ascii_lowercase()
}

/// `15 SP4` → `15.4`, matching SLES `VERSION_ID`. A release with no service
/// pack keeps its bare major.
fn sles_release(v: &str) -> String {
    let v = v.trim();
    match v.split_once(" SP") {
        Some((major, sp)) => format!("{}.{}", major.trim(), sp.trim()),
        None => series(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string here was read out of an OSV bucket on 2026-08-13; the
    /// point of the test is that the two sides meet (ADR 0022 §5).
    #[test]
    fn osv_and_os_release_agree() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("Debian:12", "debian", Some("12")),
            ("Alpine:v3.20", "alpine", Some("3.20.3")),
            ("Ubuntu:22.04:LTS", "ubuntu", Some("22.04")),
            ("Ubuntu:23.10", "ubuntu", Some("23.10")),
            ("Red Hat:enterprise_linux:8::appstream", "rhel", Some("8.9")),
            ("Rocky Linux:9", "rocky", Some("9.3")),
            ("AlmaLinux:9", "almalinux", Some("9.3")),
            (
                "openSUSE:Tumbleweed",
                "opensuse-tumbleweed",
                Some("20240328"),
            ),
            ("openSUSE:Leap 15.6", "opensuse-leap", Some("15.6")),
            (
                "openSUSE:Leap Micro 5.5",
                "opensuse-leap-micro",
                Some("5.5"),
            ),
            ("SUSE:Linux Enterprise Server 15 SP4", "sles", Some("15.4")),
            ("Azure Linux:3", "azurelinux", Some("3.0")),
            ("Azure Linux:2", "mariner", Some("2.0")),
            ("openEuler:24.03-LTS", "openeuler", Some("24.03")),
            (
                "openEuler:22.03-LTS-SP3",
                "openeuler",
                Some("22.03 (LTS-SP3)"),
            ),
            ("Mageia:9", "mageia", Some("9")),
            ("Wolfi", "wolfi", None),
            ("Chainguard", "chainguard", None),
        ];
        for (osv, id, version_id) in cases {
            let from_feed = from_osv_ecosystem(osv);
            let from_image = from_os_release(id, *version_id);
            assert!(from_feed.is_some(), "OSV `{osv}` normalized to nothing");
            assert_eq!(
                from_feed, from_image,
                "`{osv}` and os-release ID={id} VERSION_ID={version_id:?} disagree"
            );
        }
    }

    #[test]
    fn ubuntu_pro_never_matches_a_plain_release() {
        let pro = from_osv_ecosystem("Ubuntu:Pro:22.04:LTS").unwrap();
        let plain = from_osv_ecosystem("Ubuntu:22.04:LTS").unwrap();
        assert_ne!(pro, plain);
        assert_eq!(pro.distro, Distro::UbuntuPro);
        // An image never reports itself as Pro, so nothing normalizes into it.
        assert_ne!(from_os_release("ubuntu", Some("22.04")), Some(pro));
    }

    #[test]
    fn releases_do_not_cross_match() {
        assert_ne!(
            from_osv_ecosystem("Debian:11"),
            from_osv_ecosystem("Debian:12")
        );
        assert_ne!(
            from_osv_ecosystem("Alpine:v3.19"),
            from_osv_ecosystem("Alpine:v3.20")
        );
        assert_ne!(
            from_osv_ecosystem("Red Hat:enterprise_linux:8::appstream"),
            from_osv_ecosystem("Red Hat:enterprise_linux:9::appstream")
        );
        // Same release, different repo: still the same OS.
        assert_eq!(
            from_osv_ecosystem("Red Hat:enterprise_linux:9::appstream"),
            from_osv_ecosystem("Red Hat:enterprise_linux:9::baseos")
        );
        assert_eq!(
            from_osv_ecosystem("openSUSE:Leap 15.6 NonFree"),
            from_osv_ecosystem("openSUSE:Leap 15.6")
        );
    }

    #[test]
    fn non_os_ecosystems_normalize_to_nothing() {
        // Lockfile ecosystems must not be dragged through distro matching.
        for eco in ["npm", "PyPI", "crates.io", "Maven", "Go"] {
            assert_eq!(from_osv_ecosystem(eco), None, "{eco}");
        }
        // Red Hat layered products share the bucket but are not an OS.
        for eco in [
            "Red Hat:openshift:4.14::el9",
            "Red Hat:ansible_automation_platform:2.4::el9",
            "Red Hat:ceph_storage:8.1::el9",
        ] {
            assert_eq!(from_osv_ecosystem(eco), None, "{eco}");
        }
        // SUSE's non-OS products likewise.
        assert_eq!(from_osv_ecosystem("SUSE:Enterprise Storage 7.1"), None);
    }

    #[test]
    fn unresolvable_images_yield_no_key() {
        // Debian sid/testing publish no VERSION_ID (ADR 0022 §9). This is why
        // the xz backdoor's own distro would not have resolved.
        assert_eq!(from_os_release("debian", None), None);
        // OSV publishes no Fedora bucket, so a key would be unserviceable.
        assert_eq!(from_os_release("fedora", Some("40")), None);
        assert_eq!(from_os_release("arch", None), None);
    }

    #[test]
    fn buckets_cover_every_distro() {
        for eco in DISTRO_BUCKETS {
            assert!(
                from_osv_ecosystem(eco).is_some()
                    || from_osv_ecosystem(&format!("{eco}:1")).is_some()
                    || *eco == "Red Hat"
                    || *eco == "SUSE"
                    || *eco == "openSUSE",
                "bucket {eco} normalizes nothing"
            );
        }
        // Tumbleweed's advisories live in the openSUSE bucket.
        assert_eq!(
            from_osv_ecosystem("openSUSE:Tumbleweed").unwrap().bucket(),
            "openSUSE"
        );
        assert_eq!(
            from_osv_ecosystem("Ubuntu:Pro:22.04:LTS").unwrap().bucket(),
            "Ubuntu"
        );
    }
}
