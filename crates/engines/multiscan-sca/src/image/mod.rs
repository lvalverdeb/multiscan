//! Container image support (spec 7.1): OCI pull + hardened layer extraction.
//! Package-database parsing → OSV resolution lands in T-402; this module
//! delivers the pull and the security-critical extraction.

mod extract;
mod oci;

pub use extract::{extract_layer, ExtractError, Limits, Stats};
pub use oci::{OciClient, OciError, PulledImage, Reference};

use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

/// Extract all of an image's layers, in order (base first, whiteouts applied),
/// into `dest`. `dest` must already exist. Returns cumulative stats.
///
/// The whole extraction is confined beneath `dest` via a cap-std `Dir`, so no
/// entry — however malicious — can affect anything outside it (SCA-005).
pub fn extract_image(layers: &[Vec<u8>], dest: &Path) -> Result<Stats, ExtractError> {
    let root = Dir::open_ambient_dir(dest, ambient_authority())
        .map_err(|e| ExtractError::Io(e.to_string()))?;
    let limits = Limits::default();
    let mut stats = Stats::default();
    for layer in layers {
        extract_layer(layer.as_slice(), &root, &limits, &mut stats)?;
    }
    Ok(stats)
}
