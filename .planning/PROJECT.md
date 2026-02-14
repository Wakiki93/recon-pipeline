# ReconPipe

## What This Is

A Go CLI tool that orchestrates the full external recon pipeline — from subdomain discovery through vulnerability scanning — in a structured, beginner-friendly way. It chains subfinder, tlsx, dig, masscan, nmap, httpx, gowitness, cdncheck, and nuclei into a configurable pipeline with wizard-style prompts for newcomers and pipe flexibility for power users. Built for a two-person pentest team to use internally on engagements.

## Core Value

Reliable subdomain-to-vulnerability pipeline that tracks dangling DNS records across scans and diffs results over time — so nothing falls through the cracks between engagements.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] Wizard-style CLI walkthrough for beginners (enter target, pick stages, run)
- [ ] Configurable stage pipeline (run all, skip some, pause at checkpoints)
- [ ] Subdomain discovery via subfinder + tlsx
- [ ] DNS resolution via dig with unresolved subdomain tracking
- [ ] CDN detection via cdncheck (pre-scan to filter CDN IPs, post-probe to tag in reports)
- [ ] Port scanning via masscan + nmap fingerprinting (skip CDN IPs)
- [ ] HTTP probing via httpx on both raw IPs and subdomains (vhost detection)
- [ ] Screenshot capture via gowitness for visual triage
- [ ] Vulnerability scanning via nuclei against IPs and domains
- [ ] Per-stage markdown reports (subdomains.md, ports.md, http-probes.md, vulns.md, etc.)
- [ ] Dangling DNS tracking as a core feature — dedicated report, subdomain takeover candidates
- [ ] Scan diff mode — compare current vs. previous scan, highlight changes
- [ ] Scan history organized by target and date
- [ ] Pre-flight dependency check — detect missing tools, show install instructions
- [ ] Cross-platform support (Linux, macOS, WSL)
- [ ] Power-user mode — pipe-friendly, composable subcommands

### Out of Scope

- Auto-installation of external tools — user installs, CLI checks and warns
- Web UI / dashboard — CLI only for v1
- Cloud/SaaS deployment — runs locally
- Active exploitation — recon and detection only
- Custom nuclei template authoring — uses existing templates

## Context

- Two-person team: one experienced (pipes commands ad-hoc), one wants structure
- Experienced user uses cdncheck to filter CDN-hosted targets before scanning
- Unresolved subdomains are high-value: subdomain takeover candidates, abandoned DNS records that should be cleaned up
- Tool will be run repeatedly against same targets — diff mode is critical for tracking attack surface changes
- External tools are all Go-based or standard Linux utilities, most installable via `go install` or package managers
- Pipeline order: subfinder → tlsx → dig → cdncheck (pre-filter) → masscan → nmap → httpx → gowitness → cdncheck (tag) → nuclei
- Both IP-based and vhost-based HTTP probing needed (some services only respond to specific hostnames)

## Constraints

- **Language**: Go — aligns with most of the tools in the ecosystem, single binary distribution
- **Dependencies**: External tools must be on PATH — CLI orchestrates, doesn't bundle
- **Platform**: Must work on Linux, macOS, and WSL (Windows via WSL)
- **Scope**: Recon and detection only — no active exploitation capabilities

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go for implementation | Aligns with tool ecosystem (subfinder, httpx, nuclei all Go), single binary | — Pending |
| Markdown for reports | Human-readable, git-diffable, no extra tooling needed | — Pending |
| Wizard + pipe dual mode | Beginners get guided flow, power users get composability | — Pending |
| CDN check in two passes | Pre-scan filters waste (don't portscan Cloudflare), post-probe tags for reporting | — Pending |
| Dangling DNS as core feature | Subdomain takeover detection + DNS hygiene are high-value deliverables | — Pending |
| Scan diffing | Running against same targets over time demands change tracking | — Pending |

---
*Last updated: 2026-02-14 after initialization*
