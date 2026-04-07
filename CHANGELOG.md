# Changelog

## v0.1.0

New:
- firewall: application-aware network firewall with five-tier rule matching, tracker shield, and domain blocklists
- firewall: 10 net subcommands — scan, shield, rules, groups, trackers, apps, explain, log, learn, blocklists
- firewall: rule learning mode watches live connections and suggests rules from observed traffic
- firewall: GeoIP enrichment with embedded MaxMind databases for country and ASN lookups
- firewall: graylist detection for abusable Apple-signed binaries (shells, curl, python)
- firewall: essential domain safelist prevents accidentally blocking OCSP, NTP, and system update checks
- endpoint-security: Endpoint Security framework integration for real-time network AUTH event interception
- process-monitor: code signing verification, responsible process resolution, socket enumeration, and resource usage stats
- dns: passive DNS cache with LRU eviction and RFC 1035 wire parser for hostname enrichment
- apps: per-app profile database with 21 curated app profiles, categories, and breakage risk ratings
- metrics: SQLite-backed operational metrics store for enforcement, network, and sensor events
- sensors: WiFi network monitoring via CoreWLAN — SSID, BSSID, channel, noise, security mode
- sensors: screen capture detection via IOKit for screen recording awareness
- sensors: power state monitoring via IOKit for lid-close and AC/battery transitions
- sensors: network context aggregation combining WiFi, Bluetooth, and power state
- sensors: event debouncing to suppress repeated alerts within configurable windows
- status: privacy posture dashboard with 0-100 composite score across services, traces, devices, and network
- scrub: 12 artifact domains with 42 named artifacts for structured filesystem cleanup
- scrub: target by domain, by individual artifact name, or scrub all in one command
- scrub: --list shows available targets with counts and service overlap markers
- scoring: weighted privacy score combining service exposure, disk traces, device permissions, and network posture
- lookup: binary analysis via openbinary with auto-upload for unknown binaries
- knowledge: structured TOML knowledge base for apps, network groups, tracker categories, service artifacts, and service groups
- catalog: service group data moved to knowledge/services/ for unified loading
