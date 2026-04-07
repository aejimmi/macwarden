//! GeoIP lookups using MaxMind databases loaded from disk.
//!
//! Provides country code and ASN (autonomous system name) lookups for
//! IP addresses. Databases are loaded from `~/.macwarden/geo/` at runtime.
//! All lookups gracefully return `None` when databases are absent.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::Reader;

/// Expected filename for the country database.
const COUNTRY_FILENAME: &str = "GeoLite2-Country.mmdb";

/// Expected filename for the ASN database.
const ASN_FILENAME: &str = "GeoLite2-ASN.mmdb";

/// Subdirectory under `~/.macwarden/` where geo databases live.
const GEO_SUBDIR: &str = "geo";

/// Geographic and ownership info for an IP address.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. "US", "DE", "RU").
    pub country: Option<String>,
    /// Autonomous System name, truncated to the first word
    /// (e.g. "GOOGLE" instead of "GOOGLE LLC").
    pub asn_name: Option<String>,
}

/// GeoIP lookup service backed by MaxMind databases on disk.
pub struct GeoLookup {
    country_reader: Reader<Vec<u8>>,
    asn_reader: Reader<Vec<u8>>,
}

impl GeoLookup {
    /// Load databases from `~/.macwarden/geo/`.
    ///
    /// # Errors
    ///
    /// Returns `NetError::GeoIp` if the geo directory is missing or a
    /// database cannot be read/parsed.
    pub fn new() -> Result<Self, crate::error::NetError> {
        let dir = geo_dir().map_err(|e| crate::error::NetError::GeoIp {
            message: format!("failed to resolve geo directory: {e}"),
        })?;
        Self::from_dir(&dir)
    }

    /// Load databases from a specific directory.
    ///
    /// # Errors
    ///
    /// Returns `NetError::GeoIp` if a database file is missing or invalid.
    pub fn from_dir(dir: &Path) -> Result<Self, crate::error::NetError> {
        let country_path = dir.join(COUNTRY_FILENAME);
        let asn_path = dir.join(ASN_FILENAME);

        let country_reader =
            Reader::open_readfile(&country_path).map_err(|e| crate::error::NetError::GeoIp {
                message: format!("{}: {e}", country_path.display()),
            })?;
        let asn_reader =
            Reader::open_readfile(&asn_path).map_err(|e| crate::error::NetError::GeoIp {
                message: format!("{}: {e}", asn_path.display()),
            })?;

        Ok(Self {
            country_reader,
            asn_reader,
        })
    }

    /// Look up geographic and ownership info for an IP.
    ///
    /// Returns a default `GeoInfo` (all `None`) if lookups fail -- this
    /// is expected for private/reserved addresses.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let country = self.lookup_country(ip);
        let asn_name = self.lookup_asn(ip);
        GeoInfo { country, asn_name }
    }

    /// Extract ISO country code from the Country database.
    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let lookup = self.country_reader.lookup(ip).ok()?;
        let result: maxminddb::geoip2::Country<'_> = lookup.decode().ok()??;
        result.country.iso_code.map(String::from)
    }

    /// Extract ASN organization name, truncated to the first word.
    fn lookup_asn(&self, ip: IpAddr) -> Option<String> {
        let lookup = self.asn_reader.lookup(ip).ok()?;
        let result: maxminddb::geoip2::Asn<'_> = lookup.decode().ok()??;
        let full = result.autonomous_system_organization?;
        Some(truncate_asn(full))
    }
}

/// Truncate an ASN name to the first meaningful word.
///
/// "GOOGLE LLC" -> "GOOGLE", "CLOUDFLARE-NET" -> "CLOUDFLARE-NET",
/// "Amazon.com, Inc." -> "Amazon.com".
fn truncate_asn(name: &str) -> String {
    // Split on whitespace, take first token, strip trailing punctuation.
    let first = name.split_whitespace().next().unwrap_or(name);
    first.trim_end_matches(',').to_owned()
}

/// Resolve the geo database directory: `~/.macwarden/geo/`.
pub fn geo_dir() -> Result<PathBuf, std::env::VarError> {
    let home = std::env::var("HOME")?;
    Ok(PathBuf::from(home).join(".macwarden").join(GEO_SUBDIR))
}

/// Check whether geo databases are present on disk.
#[must_use]
pub fn databases_available() -> bool {
    let Ok(dir) = geo_dir() else {
        return false;
    };
    dir.join(COUNTRY_FILENAME).is_file() && dir.join(ASN_FILENAME).is_file()
}

#[cfg(test)]
#[path = "geoip_test.rs"]
mod geoip_test;
