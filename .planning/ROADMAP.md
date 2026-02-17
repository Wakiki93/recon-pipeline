# Roadmap: ReconPipe

## Overview

ReconPipe transforms from a basic Go CLI foundation into a full-featured reconnaissance orchestrator across 7 phases. The journey begins with data storage and configuration infrastructure, builds through progressive tool integration (subdomains -> CDN filtering -> port scanning -> HTTP probing -> vulnerability detection), adds competitive differentiators (scan diffing and dangling DNS tracking), and culminates with production-ready pipeline orchestration featuring wizard mode, resume capability, and safety features. Each phase delivers verifiable capabilities that compound into a reliable subdomain-to-vulnerability pipeline.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation & Configuration** - Data models, storage, config loading *(completed 2026-02-16)*
- [ ] **Phase 2: Subdomain Discovery** - subfinder + tlsx + dig + deduplication
- [ ] **Phase 3: CDN Detection & Port Scanning** - cdncheck pre-filtering + masscan + nmap
- [ ] **Phase 4: HTTP Probing & Screenshots** - httpx vhost detection + gowitness
- [ ] **Phase 5: Vulnerability Scanning** - nuclei integration with severity filtering
- [ ] **Phase 6: Scan Tracking & Diff Mode** - Historical comparison + dangling DNS tracking
- [ ] **Phase 7: Pipeline Orchestration & UX** - Full pipeline + wizard + resume + safety

## Phase Details

### Phase 1: Foundation & Configuration
**Goal**: Establish data models, persistent storage, and configuration infrastructure that all subsequent phases depend on

**Depends on**: Nothing (first phase)

**Requirements**: CONF-01, CONF-02

**Success Criteria** (what must be TRUE):
  1. User can define tool parameters and rate limits in a YAML config file
  2. User can run CLI and see which required external tools are missing with install instructions
  3. Scan results are saved to structured directories (scans/domain_timestamp/)
  4. Basic scan metadata (target, start time, tool versions) persists to bbolt database

**Plans:** 3 plans

Plans:
- [x] 01-01-PLAN.md — Go module init, data models, YAML config loading
- [x] 01-02-PLAN.md — bbolt storage layer and scan directory structure
- [x] 01-03-PLAN.md — Cobra CLI with check and init commands

### Phase 2: Subdomain Discovery
**Goal**: Deliver working subdomain enumeration pipeline with deduplication and DNS resolution

**Depends on**: Phase 1

**Requirements**: DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, PIPE-01 (basic), REPT-01 (basic)

**Success Criteria** (what must be TRUE):
  1. User can run one command to discover subdomains for a target domain using subfinder and tlsx
  2. Discovered subdomains are deduplicated across both sources
  3. User sees which subdomains resolved to IPs via dig and which failed DNS resolution
  4. Unresolved subdomains are flagged separately as dangling DNS candidates
  5. Pipeline produces a subdomains.md markdown report listing all findings

**Plans:** 2 plans

Plans:
- [ ] 02-01-PLAN.md — Tool wrappers (subfinder/tlsx/dig), discovery pipeline, deduplication, DNS resolution
- [ ] 02-02-PLAN.md — Markdown report generator and discover CLI command

### Phase 3: CDN Detection & Port Scanning
**Goal**: Filter CDN-hosted IPs before port scanning and fingerprint open ports on remaining targets

**Depends on**: Phase 2

**Requirements**: CDN-01, CDN-02, PORT-01, PORT-02, PORT-03

**Success Criteria** (what must be TRUE):
  1. User can check resolved IPs against CDN providers via cdncheck before port scanning
  2. CDN-hosted IPs are excluded from masscan and nmap scans
  3. User can run fast port discovery on non-CDN IPs via masscan
  4. Discovered open ports are fingerprinted by nmap for service/version identification
  5. Port scan results associate both IPs and their corresponding subdomains
  6. Pipeline produces a ports.md report showing open ports per host

**Plans:** 2 plans

Plans:
- [ ] 03-01-PLAN.md — Tool wrappers for cdncheck, masscan, and nmap
- [ ] 03-02-PLAN.md — CDN filtering pipeline, port scan orchestration, report, and CLI command

### Phase 4: HTTP Probing & Screenshots
**Goal**: Detect live HTTP services with vhost awareness and capture screenshots for visual triage

**Depends on**: Phase 3

**Requirements**: HTTP-01, HTTP-02, HTTP-03, HTTP-04, CDN-03

**Success Criteria** (what must be TRUE):
  1. User can probe discovered hosts for HTTP/HTTPS services via httpx on both raw IPs and subdomains
  2. HTTP probing runs on all discovered open ports, not just 80/443
  3. Vhost-bound services are detected (services that only respond to specific hostnames)
  4. User can capture screenshots of live HTTP services via gowitness
  5. HTTP probe results tag CDN provider identification (post-probe tagging)
  6. Pipeline produces http-probes.md report with live services and screenshot paths

**Plans**: TBD

Plans:
- [ ] 04-01: TBD during plan-phase
- [ ] 04-02: TBD during plan-phase

### Phase 5: Vulnerability Scanning
**Goal**: Integrate nuclei for vulnerability detection with configurable severity filtering

**Depends on**: Phase 4

**Requirements**: VULN-01, VULN-02, VULN-03

**Success Criteria** (what must be TRUE):
  1. User can run nuclei against discovered IPs and subdomains
  2. Vulnerability results include severity level, affected host, and template ID
  3. User can filter nuclei templates by severity level (critical/high/medium/low)
  4. Pipeline produces vulns.md report organized by severity
  5. Zero findings do not crash pipeline (empty report is valid output)

**Plans**: TBD

Plans:
- [ ] 05-01: TBD during plan-phase
- [ ] 05-02: TBD during plan-phase

### Phase 6: Scan Tracking & Diff Mode
**Goal**: Enable historical scan comparison and persistent dangling DNS tracking across engagements

**Depends on**: Phase 5

**Requirements**: TRCK-01, TRCK-02, TRCK-03, TRCK-04, REPT-03

**Success Criteria** (what must be TRUE):
  1. User can run diff mode to compare current scan against previous scan for same target
  2. Diff report highlights new/removed subdomains, ports, and vulnerabilities in human-readable format
  3. Scan history is stored per-target with timestamped entries viewable via CLI
  4. Dangling DNS records are tracked across scans to identify persistent vs. newly-appeared unresolved subdomains
  5. Pipeline produces dedicated dangling-dns.md report listing subdomain takeover candidates with CNAME records
  6. User can see what changed in attack surface between engagements at a glance

**Plans**: TBD

Plans:
- [ ] 06-01: TBD during plan-phase
- [ ] 06-02: TBD during plan-phase
- [ ] 06-03: TBD during plan-phase

### Phase 7: Pipeline Orchestration & UX
**Goal**: Deliver production-ready full pipeline with wizard mode, resume capability, and safety features

**Depends on**: Phase 6

**Requirements**: PIPE-02, PIPE-03, PIPE-04, PIPE-05, PIPE-06, PIPE-07, REPT-02, REPT-04, CONF-03, CONF-04, CONF-05

**Success Criteria** (what must be TRUE):
  1. User can configure which pipeline stages to run, skip, or pause at via flags or config
  2. Pipeline resumes from last successful stage after a failure without re-running completed work
  3. A single tool crash does not terminate the entire pipeline (crash isolation)
  4. User sees real-time progress showing current stage, completion status, and elapsed time
  5. User can run wizard mode that walks through target entry and stage selection interactively
  6. User can pipe tool outputs to stdin/stdout for composability with external scripts
  7. User can define scope boundaries (domain allowlist, CIDR ranges) to prevent out-of-scope scanning
  8. User can select from preset workflow templates (bug bounty, internal pentest, quick recon)
  9. User can configure notification hooks (Slack/Discord/webhook) for scan completion events
  10. Pipeline produces structured log files for debugging and audit trails
  11. Reports are organized in per-target directories following scans/domain_timestamp/ structure

**Plans**: TBD

Plans:
- [ ] 07-01: TBD during plan-phase
- [ ] 07-02: TBD during plan-phase
- [ ] 07-03: TBD during plan-phase
- [ ] 07-04: TBD during plan-phase

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation & Configuration | 3/3 | Complete | 2026-02-16 |
| 2. Subdomain Discovery | 0/2 | In progress | - |
| 3. CDN Detection & Port Scanning | 0/2 | Not started | - |
| 4. HTTP Probing & Screenshots | 0/2 | Not started | - |
| 5. Vulnerability Scanning | 0/2 | Not started | - |
| 6. Scan Tracking & Diff Mode | 0/3 | Not started | - |
| 7. Pipeline Orchestration & UX | 0/4 | Not started | - |

---
*Roadmap created: 2026-02-14*
*Last updated: 2026-02-17*
