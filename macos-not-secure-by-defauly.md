# macOS: Not Secure by Default — The Discourse

## The Scale of the Problem

Your Mac runs **500+ processes at idle**. Howard Oakley (Eclectic Light Company) has documented that a vanilla Mac with no apps open exceeds 700 processes. The system ships with **418 system daemons**, **460 system agents**, and as of macOS 26 Tahoe, a new category called **Launch Angels**.

Community scripts cataloguing disableable services have identified **90-117 services** in Sequoia and **95+ in Tahoe** that most users don't need.

Sources:
- [Howard Oakley: Launch Angels](https://eclecticlight.co/2025/10/03/welcome-to-tahoes-launch-angels/)
- [b0gdanw: Disable Sequoia Bloatware](https://gist.github.com/b0gdanw/b349f5f72097955cf18d6e7d8035c665)
- [b0gdanw: Disable Tahoe Bloatware](https://gist.github.com/b0gdanw/0c20c2fd5d0a7e6cff01849b57108967)
- [Renoise: Daemon Minimization Thread](https://forum.renoise.com/t/macos-12-13-14-15-system-daemon-minimization/68972)

---

## "Off" Doesn't Mean Off

This is one of the most independently verified claims across the community.

**Howard Oakley** (January 2026) confirmed definitively: *"It's not possible in macOS Tahoe to completely disable either Siri or Spotlight"* without disabling SIP. Toggle switches *"function more as suggestions than commands."* Processes like `siriactionsd`, `siriknowledged`, `mds`, `spotlightknowledged` persist after disabling.

**Privacy Guides Community** documented **27 specific daemons** attempting internet access despite being disabled in System Settings, including: `adprivacyd`, `AMPLibraryAgent`, `amsaccountsd`, `amsengagementd`, `cloudd`, `parsecd`, `promotedcontentd`, `Spotlight`, `tipsd`, `triald`, and more.

**Lloyd Chambers** (Mac Performance Guide) documented 18+ background processes running despite being disabled, including `photoanalysisd`, `findmydeviced`, and Siri-related services.

Sources:
- [Oakley: Can You Disable Spotlight and Siri?](https://eclecticlight.co/2026/01/16/can-you-disable-spotlight-and-siri-in-macos-tahoe/)
- [Privacy Guides: Blocked Internet Access to macOS Daemons](https://discuss.privacyguides.net/t/blocked-internet-access-to-macos-daemons-agents/12223)
- [Mac Performance Guide: macOS Bloatware](https://macperformanceguide.com/blog/2017/20170110_1000-macOS-bloatWare.html)

---

## On-Device ML Profiling Is Deep

**Sarah Edwards** (mac4n6.com, digital forensics researcher) showed in foundational 2018 research that `knowledgeC.db` captures: app usage frequency/duration, Safari browsing history, device power states, audio routing, communication participants, and location. Four weeks retained.

**SentinelOne/SentinelLabs** documented that this data is *"scrapable by processes running with the user's privileges, but not necessarily their knowledge."*

Starting with macOS Ventura, Apple migrated to **Biome** — a proprietary protobuf-encoded format that stores the same data at *higher granularity* in a format intentionally harder to inspect than SQLite.

**Specific profiling daemons:**
- `coreduetd` — runs ML classifiers (decision trees, gradient-boosted, random forests) to fingerprint users
- `duetexpertd` — ranks apps, contacts, and actions for "proactive" suggestions
- `suggestd` — scans messages and documents to extract entities
- `biomesyncd` — syncs behavioral data across devices
- `routined` — learns location patterns, predicts future visits
- `intelligenceplatformd` — builds a "general purpose knowledge graph"

In Tahoe, new daemons were added: `intelligenceflowd`, `intelligencecontextd`, `generativeexperiencesd`, `knowledgeconstructiond`.

Sources:
- [Sarah Edwards: knowledgeC.db](http://www.mac4n6.com/blog/2018/8/5/knowledge-is-power-using-the-knowledgecdb-database-on-macos-and-ios-to-determine-precise-user-and-application-usage)
- [SentinelOne: macOS User Data](https://www.sentinelone.com/labs/macos-incident-response-part-2-user-data-activity-and-behavior/)
- [Biome Forensics](https://blog.d204n6.com/2022/09/ios-16-now-you-c-it-now-you-dont.html)
- [Cevher Dogan: Hidden AI Drain](https://medium.com/@cevherd/the-hidden-ai-drain-on-my-mac-spotlight-or-surveillance-a4d2ce19e5ef)

---

## Every Daemon Is Attack Surface — Proven Repeatedly

### 2025-2026 Highlights

**Microsoft Threat Intelligence — "Sploitlight" (CVE-2025-31199, July 2025):** Spotlight-based TCC bypass that can extract data *cached by Apple Intelligence* — geolocation, face recognition data, photo metadata, search history. Cross-device: attacker on one Mac can access iCloud-linked device data. This is the smoking gun — Apple Intelligence caches *expand* what attackers can steal.
- [Microsoft Blog](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)

**Microsoft — CVE-2025-31191 (May 2025):** Generic sandbox escape via security-scoped bookmarks affecting *any sandboxed app*.
- [Microsoft Blog](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)

**Mickey Jin — CVE-2025-43530 (December 2025):** Complete TCC bypass allowing silent access to microphone, camera, and documents.
- [eSecurity Planet](https://www.esecurityplanet.com/threats/macos-flaw-enables-silent-bypass-of-apple-privacy-controls/)

**Google TAG — CVE-2026-20700 (February 2026):** dyld zero-day, CVSS 7.8, used in targeted attacks. Apple called it *"extremely sophisticated."* CISA set federal compliance deadline.
- [Help Net Security](https://www.helpnetsecurity.com/2026/02/12/apple-zero-day-fixed-cve-2026-20700/)

**Apple patched 9 zero-days exploited in the wild in 2025 alone.**

**Mickey Jin (2024):** Found 10+ sandbox escape vulnerabilities in XPC services including `AudioAnalyticsHelperService.xpc`, `ShortcutsFileAccessHelper.xpc` (full disk access tokens), and `mscamerad-xpc.xpc` (photo access).
- [Jin: New Era of Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)

**Csaba Fitzl (Black Hat Europe 2024):** Sandbox escapes, privilege escalations, and TCC bypasses in `diskarbitrationd` and `storagekitd`.
- [Kandji Blog](https://blog.kandji.io/macos-audit-story-part1)

### Patrick Wardle (Objective-See)

Former NSA (Malicious Code Analysis), former NASA. Creator of Objective-See, author of *The Art of Mac Malware*, founder of Objective by the Sea conference.

- **DEF CON 26 (2018):** Demonstrated trivial bypasses of Little Snitch. Apple's own services were effectively unmonitorable.
- **DEF CON 31 (2023):** Three bypasses of Apple's Background Task Management, two requiring no root. *"Any malware that's somewhat sophisticated can trivially bypass the monitoring."*
- **ContentFilterExclusionList:** Discovered Apple exempted ~50 of its own processes from third-party firewalls/VPNs. Removed after public outcry.
- **Mac Malware of 2025 (January 2026):** Documents the malware explosion — stealers, MaaS, triple-persistence techniques, North Korean campaigns. *"macOS malware is becoming more common, more capable, and more insidious with each passing year."*

Sources:
- [Wardle DEF CON 26](https://speakerdeck.com/patrickwardle/fire-and-ice-making-and-breaking-macos-firewalls)
- [Wardle DEF CON 31](https://speakerdeck.com/patrickwardle/demystifying-and-bypassing-macoss-background-task-management)
- [Mac Malware of 2025](https://objective-see.org/blog/blog_0x84.html)

---

## Apple Intelligence: The Latest Battleground

**Lumia Security — "AppleStorm" (Black Hat 2025):** Siri sends dictated message content, recipient phone numbers, installed app lists, and precise geolocation to Apple servers *outside Private Cloud Compute*. Two identical queries can trigger completely different privacy frameworks. Apple *"respectfully disagrees."*
- [CyberScoop](https://cyberscoop.com/apple-intelligence-privacy-siri-whatsapp-lumia-security-black-hat-2025/)
- [Lumia Security](https://www.lumia.security/blog/applestorm)

**Cannot be fully removed.** Only toggled off. Users report it re-enables after updates. Consumes ~7GB that isn't freed when disabled. `assistantd` uses 18-22% CPU every 90 seconds even with features "off."

**Moonlock Lab** raised concerns that Apple Intelligence's content review capabilities could be exploited through zero-days, and that new cross-device features expand the attack surface.
- [Moonlock](https://moonlock.com/new-macos-tahoe-features)

---

## The SIP Paradox

SIP protects against malware modifying system files. SSV (Sealed System Volume) cryptographically verifies every system file. But they also prevent users from disabling Apple's own unwanted daemons.

**You must weaken system security to gain privacy control.** This is the fundamental architectural catch-22.

Microsoft even found a way to bypass SIP itself through kernel extensions (CVE-2024-44243, January 2025).
- [Microsoft Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

---

## Apple's Response Pattern (2025-2026)

- **AppleStorm findings:** *"Respectfully disagrees."* Recharacterized as third-party SiriKit issue.
- **Security bounties slashed (December 2025):** TCC bypass bounties cut from $30,500 to $5,000 — an 83% reduction. Csaba Fitzl: *"Apple admits we can't fix this."* This incentivizes selling vulnerabilities on the black market instead.
- **UK encryption standoff:** Pulled Advanced Data Protection entirely for UK users rather than comply with backdoor order.
- **Private Cloud Compute:** Zero outsourced audits. Trust is entirely Apple's word.
- **Automatic updates (Tahoe 26.1):** Security updates now install regardless of settings — reducing user control further.

Sources:
- [9to5Mac: Bounties Slashed](https://9to5mac.com/2025/12/02/apple-security-bounties-slashed-as-mac-malware-grows/)
- [Washington Post: UK Encryption](https://www.washingtonpost.com/technology/2025/02/07/apple-encryption-backdoor-uk/)
- [Oakley: Automatic Updates](https://eclecticlight.co/2025/11/06/how-tahoe-26-1-has-enabled-automatic-security-updates/)

---

## What the Community Says (2025-2026)

**Hacker News** discussions show mixed but increasingly skeptical sentiment:
- *"All the software is closed source"* and *"you don't have the encryption keys"* — verification impossible
- Apple's $20B/year Google search deal conflicts with privacy positioning
- iCloud backups default to unencrypted (Advanced Data Protection is opt-in), affecting 99.9% of users
- [HN: Apple Platform Security](https://news.ycombinator.com/item?id=46837814)
- [HN: AppleStorm](https://news.ycombinator.com/item?id=44974109)

**Michael Swengel (February 2026):** *"Yes, Your Mac IS Spying on You"* — documents data collection even when users decline analytics. Notes telemetry built into Apple apps *cannot be disabled*.
- [Medium](https://medium.com/@michaelswengel/yes-your-mac-is-watching-you-6d1f25b6fa59)

**Moonlock 2025 Threat Report:** 66% of Mac users encountered threats in the past year. 67% increase in backdoor variants. 300% spike in Atomic Stealer infections. MaaS pricing dropped to $1,000-3,000/month.
- [Moonlock Report](https://moonlock.com/2025-macos-threat-report)

**Krypto IT (2026):** The Mac "immunity myth" is now a primary entry point for high-value breaches. The *"Confidence Gap"* — Mac users being less cautious — is the biggest vulnerability.
- [Krypto IT](https://www.kryptocybersecurity.com/the-apple-myth-why-your-mac-is-still-at-risk-in-2026/)

---

## The Jeffrey Paul Incident (November 2020)

**Jeffrey Paul** (sneak.berlin) published *"Your Computer Isn't Yours"* — arguing macOS Big Sur sends unencrypted OCSP requests containing developer certificate hashes to Apple on every app launch. `trustd` was placed in `ContentFilterExclusionList`, making it unblockable by user firewalls/VPNs.

**Technical correction:** Jacopo Jannone (blog.jacopo.io) found that `trustd` sends developer certificate serial numbers, not unique app hashes — Apple receives developer identity, not specific application identity. This corrects Paul's specific claim but does not eliminate the privacy concern.

Sources:
- [Jeffrey Paul: Your Computer Isn't Yours](https://sneak.berlin/20201112/your-computer-isnt-yours/)
- [Jacopo Jannone: Does Apple Really Log Every App You Run?](https://blog.jacopo.io/en/post/apple-ocsp/)
- [MacRumors Coverage](https://www.macrumors.com/2020/11/15/apple-privacy-macos-app-authenticaion/)

---

## XPC Services as Attack Surface

**Mickey Jin** (2024) published "A New Era of macOS Sandbox Escapes" documenting a previously overlooked attack surface: XPC services in the PID domain within system frameworks. Found 10+ new sandbox escape vulnerabilities. Key finding: App Sandbox quarantines dropped files, but XPC service sandboxes do not quarantine output files by default — creating a consistent escape pathway.
- [Jin: New Era of Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)

**Csaba Fitzl** (Kandji) audited `diskarbitrationd` and `storagekitd`, finding sandbox escapes, privilege escalations, and TCC bypasses.
- [Kandji Blog](https://blog.kandji.io/macos-audit-story-part1)

**Microsoft** discovered "HM Surf" (CVE-2024-44133) bypassing TCC for Safari.

**Wojciech Regula** presented "Abusing & Securing XPC in macOS apps" at Objective by the Sea v3, documenting code injection techniques against poorly-validated XPC services.
- [OBTS Presentation](https://objectivebythesea.org/v3/talks/OBTS_v3_wRegu%C5%82a.pdf)

**Howard Oakley** noted that *"many XPC services are ripe for exploitation"* and that *"plenty of apps have been found to fall short of being suitably robust"* in their XPC service validation.
- [Oakley: XPC Explainer](https://eclecticlight.co/2026/02/07/explainer-xpc/)

---

## EU/DMA Regulatory Pressure

**European Commission (April 2025):** Found Apple in breach of DMA Article 5(4) — App Store anti-steering terms illegally restricted developers.

**Developer Coalition (December 2025):** Open letter arguing Apple has delivered *"no meaningful changes or proposals"* despite the non-compliance finding.
- [The Register](https://www.theregister.com/2025/12/16/apple_dma_complaint)

**US Diplomatic Intervention (December 2025):** Trump Administration threatened retaliation over EU DMA enforcement against U.S. tech companies.
- [MacRumors](https://www.macrumors.com/2025/12/16/trump-admin-eu-dma-retaliation/)

**Important caveat:** DMA gatekeeper designation applies to iOS, iPadOS, App Store, and Safari — not macOS directly. But the broader regulatory pressure on Apple's control model has implications across all platforms.

---

## Enterprise and Compliance Perspective

**Jamf (2025-2026):** Built CIS and NIST compliance benchmarks directly into Jamf Pro. Prediction: *"Mac will become the dominant enterprise endpoint by 2030"* — directly correlating with malware evolution.
- [Jamf Blog](https://www.jamf.com/blog/mac-management-security-trends-enterprise-it-2025/)

**CIS Benchmarks (November 2025):** New CIS Checklist for macOS 26, Level 1 and Level 2 baselines.
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/apple_os)

**NIST mSCP:** Updated for Tahoe before its September 2025 release. Generates baselines for CIS, NIST 800-53, NIST 800-171, DISA STIG, CNSSI-1253, and CMMC.
- [NIST mSCP](https://github.com/usnistgov/macos_security)

**ERNW (February 2026):** First Tahoe hardening guide. Notes *"Apple Intelligence features require explicit disabling for high-security deployments."*
- [ERNW Guide](https://github.com/ernw/hardening/blob/master/operating_system/osx/26/Hardening_Guide-macOS_26_Tahoe_1.0.md)

**SANS Institute:** Found unified logs capture *deeper host-level telemetry that EDR tools miss*.
- [SANS Presentation](https://www.sans.org/presentations/macos-telemetry-vs-edr-telemetry-which-is-better)

---

## Existing Tools and Solutions

| Tool | Author | What It Does |
|---|---|---|
| **LuLu** | Objective-See (Wardle) | Free open-source outbound firewall |
| **Little Snitch** | Objective Development | Commercial per-app firewall |
| **KnockKnock/BlockBlock** | Objective-See | Persistence detection/monitoring |
| **OverSight** | Objective-See | Mic/camera monitoring |
| **Moonlock** | MacPaw | Standalone real-time security app (Oct 2025) |
| **LaunchControl** | soma-zone | GUI for managing launchd services |
| **macOS Silverback-Debloater** | Wamphyre | Service disabling with dry-run and restore |
| **drduh Guide** | Community (20k+ stars) | Comprehensive hardening guide |
| **NIST mSCP** | NIST/NASA/DISA/LANL | Federal compliance baselines |
| **ERNW Guide** | ERNW (Feb 2026) | First Tahoe hardening guide |
| **CIS Benchmarks** | CIS (Nov 2025) | Enterprise security baselines |

Sources:
- [Objective-See Tools](https://objective-see.org/tools.html)
- [drduh Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [NIST mSCP](https://github.com/usnistgov/macos_security)
- [ERNW Tahoe Guide](https://github.com/ernw/hardening/blob/master/operating_system/osx/26/Hardening_Guide-macOS_26_Tahoe_1.0.md)
- [Silverback-Debloater](https://github.com/Wamphyre/macOS_Silverback-Debloater)

---

## What Nobody Has Built Yet

No cohesive tool exists that:
1. Discovers all running services
2. Groups them by function (telemetry, AI, sync, etc.)
3. Explains what each one does
4. Lets you block/allow by group
5. Enforces your choices across reboots
6. Works with SIP enabled
7. Provides undo/recovery
