//! Well-known port to service name mapping.
//!
//! Returns `None` for ports that are ubiquitous (e.g. 443/HTTPS) to
//! avoid cluttering the display. Returns a label for ports where the
//! service name adds useful context.

/// Look up a service name for a port number.
///
/// Returns `None` for common ports like 443 (HTTPS) that don't need
/// labeling, and for unrecognized ports.
pub fn service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-Data"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 => Some("DHCP"),
        68 => Some("DHCP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        123 => Some("NTP"),
        143 => Some("IMAP"),
        443 => None, // HTTPS is the default, don't clutter
        465 => Some("SMTPS"),
        500 => Some("IKE"),
        587 => Some("SMTP"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1194 => Some("OpenVPN"),
        1723 => Some("PPTP"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        4070 => Some("Spotify"),
        5060 => Some("SIP"),
        5222 => Some("XMPP"),
        5228 => Some("GCM"),
        5353 => Some("mDNS"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        9090 => Some("Prometheus"),
        11211 => Some("Memcached"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}
