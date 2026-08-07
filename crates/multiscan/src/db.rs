//! `multiscan db` — feed database management. `db update` is the ONLY
//! command permitted to fetch feeds (FD-003).

use anyhow::Result;
use multiscan_feeds::{cache_dir, current_snapshot, FeedClient, FeedSources};

use crate::cli::DbCmd;
use crate::exit::Exit;

pub fn run(action: &DbCmd) -> Result<Exit> {
    match action {
        DbCmd::Update => update(),
        DbCmd::Status => status(),
        DbCmd::Path => {
            println!("{}", cache_dir().display());
            Ok(Exit::Clean)
        }
        DbCmd::Export { out } => export(out),
        DbCmd::Import {
            bundle,
            trusted_key,
        } => import(bundle, trusted_key.as_deref()),
    }
}

fn export(out: &std::path::Path) -> Result<Exit> {
    let cache = cache_dir();
    let key = match multiscan_feeds::load_or_create_signing_key(&cache) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("multiscan: error: {e}");
            return Ok(Exit::FeedsStale);
        }
    };
    match multiscan_feeds::export_bundle(&cache, out, &key) {
        Ok(snapshot_id) => {
            let pubkey = multiscan_feeds::to_hex(&multiscan_feeds::public_key_bytes(&key));
            eprintln!(
                "multiscan: exported snapshot {snapshot_id} to {} (signer {pubkey})",
                out.display()
            );
            Ok(Exit::Clean)
        }
        Err(e) => {
            eprintln!("multiscan: error: db export failed: {e}");
            Ok(Exit::FeedsStale)
        }
    }
}

fn import(bundle: &std::path::Path, trusted_key: Option<&str>) -> Result<Exit> {
    let trusted = match trusted_key {
        Some(hex) => match multiscan_feeds::parse_public_key_hex(hex) {
            Some(key) => Some(key),
            None => {
                eprintln!("multiscan: error: --trusted-key must be 32-byte hex");
                return Ok(Exit::Usage);
            }
        },
        None => None,
    };
    match multiscan_feeds::import_bundle(&cache_dir(), bundle, trusted) {
        Ok(snapshot_id) => {
            eprintln!("multiscan: imported snapshot {snapshot_id}");
            Ok(Exit::Clean)
        }
        Err(e) => {
            eprintln!("multiscan: error: db import failed: {e}");
            Ok(Exit::FeedsStale)
        }
    }
}

fn update() -> Result<Exit> {
    let mut sources = FeedSources::default();
    // Opt-in secrets rule-pack feed (ADR 0010). Setting MULTISCAN_RULES_URL
    // both configures the fetch and — since the operator explicitly chose
    // this host — allow-lists it for the feed client (R-6: the allow-list
    // only ever widens by explicit operator action, never silently).
    let client = match std::env::var("MULTISCAN_RULES_URL")
        .ok()
        .filter(|u| !u.is_empty())
    {
        Some(url) => {
            let allow = multiscan_feeds::DEFAULT_ALLOWED_HOSTS
                .iter()
                .map(|h| h.to_string())
                .chain(feed_host(&url));
            sources.rules_url = Some(url);
            FeedClient::with_allowlist(allow)
        }
        None => FeedClient::new(),
    };
    match multiscan_feeds::update(&client, &sources, &cache_dir(), chrono::Utc::now()) {
        Ok(_) => Ok(Exit::Clean),
        Err(err) => {
            eprintln!("multiscan: db update failed: {err}");
            Ok(Exit::FeedsStale)
        }
    }
}

/// The host component of a URL, for allow-listing. `FeedClient::fetch`
/// re-parses and re-validates (https + allow-list) before connecting, so this
/// only needs to extract the host to widen the list; a malformed URL yields
/// no host and the fetch is refused.
fn feed_host(url: &str) -> Option<String> {
    let authority = url.split("://").nth(1)?.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

fn status() -> Result<Exit> {
    match current_snapshot(&cache_dir()) {
        Ok(Some(snapshot)) => {
            let m = &snapshot.manifest;
            println!("snapshot   {}", m.snapshot_id);
            println!("as_of      {}", m.as_of.to_rfc3339());
            println!("kev        {} entries", m.counts.kev);
            println!("epss       {} scores", m.counts.epss);
            for (ecosystem, count) in &m.counts.osv {
                println!("osv        {ecosystem}: {count} advisories");
            }
            for (name, meta) in &m.files {
                println!("file       {name}  {}  {} bytes", meta.digest, meta.bytes);
            }
            // A-3: OSV attribution appears in db status.
            println!();
            println!(
                "Advisory data from OSV (https://osv.dev), consumed under its published terms."
            );
            println!("Exploit data: EPSS (https://www.first.org/epss/) and CISA KEV.");
            Ok(Exit::Clean)
        }
        Ok(None) => {
            println!("no feed snapshot; run `multiscan db update`");
            Ok(Exit::Clean)
        }
        Err(err) => {
            eprintln!("multiscan: feed cache is corrupt: {err}");
            Ok(Exit::FeedsStale)
        }
    }
}
