//! Streaming SHA-256 file hasher.
//!
//! Reads files in 64KB chunks instead of loading the entire file into memory.
//! For a 1GB binary, this uses 64KB instead of 1GB.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::InventoryError;

/// Buffer size for streaming hash reads (8 KiB).
const BUF_SIZE: usize = 8 * 1024;

/// SHA-256 hash a file using streaming reads. Returns lowercase hex.
pub fn hash_file(path: &Path) -> Result<String, InventoryError> {
    let mut file = std::fs::File::open(path).map_err(|e| InventoryError::Hash {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let n = file.read(&mut buf).map_err(|e| InventoryError::Hash {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).expect("n <= buf.len()"));
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
#[path = "hash_test.rs"]
mod hash_test;
