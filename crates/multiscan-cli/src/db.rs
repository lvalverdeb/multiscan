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
        DbCmd::Export | DbCmd::Import => {
            eprintln!("multiscan: `db export/import` is not implemented yet (lands in T-306)");
            Ok(Exit::Usage)
        }
    }
}

fn update() -> Result<Exit> {
    let client = FeedClient::new();
    let sources = FeedSources::default();
    match multiscan_feeds::update(&client, &sources, &cache_dir(), chrono::Utc::now()) {
        Ok(_) => Ok(Exit::Clean),
        Err(err) => {
            eprintln!("multiscan: db update failed: {err}");
            Ok(Exit::FeedsStale)
        }
    }
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
