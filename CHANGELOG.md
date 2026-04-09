# Changelog

## v0.1.2

New:
- inventory: scan installed apps and system binaries — discover, hash, verify code signatures, and flag known-bad binaries
- inventory: batch openbinary lookup processes all unanalyzed binaries in one command
- firewall: live per-app connection view shows active traffic grouped by application
- firewall: drill into any app to see per-destination verdicts, ports, and tracker flags
- firewall: quick block and unblock for apps, domains, or scoped app+domain combinations
- firewall: import rules from LuLu for instant migration to macwarden
- dns: cache persists across daemon restarts with crash-safe storage and warm-start loading
- lookup: endpoint reachability test when run with no arguments
- lookup: richer output shows title and summary from openbinary analysis
- scoring: privacy dashboard tracks total internet connections alongside tracker count

## v0.1.1

Fix:
- build: sensors and process-monitor crates compile on Linux CI without framework link errors
- build: cargo deny no longer rejects the project's own GPL-3.0 license

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
