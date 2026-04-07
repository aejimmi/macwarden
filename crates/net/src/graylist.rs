//! Graylist of abusable Apple-signed binaries.
//!
//! These are macOS system binaries that are signed by Apple but should NOT
//! be auto-allowed when a profile says "allow Apple-signed processes."
//! Shells, network tools, scripting runtimes, and system utilities with
//! network capability can be co-opted by malware to exfiltrate data.
//!
//! Pattern adopted from LuLu (Objective-See).

/// Abusable Apple-signed binaries that must always be evaluated against
/// rules, even when a profile says "allow Apple-signed processes."
///
/// These paths are matched case-sensitively and exactly (no prefix or
/// glob matching). The list is intentionally small and curated.
const GRAYLIST: &[&str] = &[
    // Shells -- can execute anything
    "/bin/bash",
    "/bin/zsh",
    "/bin/sh",
    "/bin/ksh",
    "/bin/tcsh",
    "/bin/csh",
    // Network tools -- common in malware staging
    "/usr/bin/curl",
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/ftp",
    "/usr/bin/telnet",
    "/usr/bin/whois",
    // Scripting languages -- can download and execute
    "/usr/bin/perl",
    "/usr/bin/python3",
    "/usr/bin/ruby",
    // System utilities with network capability
    "/usr/bin/osascript",
    "/usr/sbin/mDNSResponder",
];

/// Returns `true` if the given executable path is a graylisted Apple binary.
///
/// Graylisted binaries are evaluated against rules even when a profile
/// says "allow Apple-signed processes." This prevents malware from using
/// legitimate Apple tools (curl, bash, python3) as exfiltration vectors.
///
/// Matching is case-sensitive and exact -- no prefix or glob matching.
///
/// # Examples
///
/// ```
/// use net::graylist::is_graylisted;
///
/// assert!(is_graylisted("/usr/bin/curl"));
/// assert!(is_graylisted("/bin/bash"));
/// assert!(!is_graylisted("/Applications/Safari.app/Contents/MacOS/Safari"));
/// ```
pub fn is_graylisted(path: &str) -> bool {
    GRAYLIST.contains(&path)
}

/// Returns the number of entries in the graylist.
///
/// Useful for CLI summary output.
pub fn count() -> usize {
    GRAYLIST.len()
}

#[cfg(test)]
#[path = "graylist_test.rs"]
mod graylist_test;
