# Requirements: ReconPipe

**Defined:** 2026-02-14
**Core Value:** Reliable subdomain-to-vulnerability pipeline that tracks dangling DNS records across scans and diffs results over time

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Pipeline Orchestration

- [ ] **PIPE-01**: User can run full pipeline from subdomain discovery through vulnerability scanning in one command
- [ ] **PIPE-02**: User can configure which stages to run, skip, or pause at via flags or config
- [ ] **PIPE-03**: Pipeline resumes from last successful stage after a failure
- [ ] **PIPE-04**: A single tool crash does not terminate the entire pipeline run
- [ ] **PIPE-05**: User sees real-time progress (current stage, completion status, elapsed time)
- [ ] **PIPE-06**: User can run wizard mode that walks through target entry and stage selection interactively
- [ ] **PIPE-07**: User can pipe tool outputs to stdin/stdout for composability with external scripts

### Subdomain Discovery

- [ ] **DISC-01**: User can discover subdomains for a target domain via subfinder
- [ ] **DISC-02**: User can discover additional subdomains/certificates via tlsx
- [ ] **DISC-03**: Discovered subdomains are deduplicated across sources
- [ ] **DISC-04**: User can resolve discovered subdomains to IPs via dig
- [ ] **DISC-05**: Subdomains that fail DNS resolution are flagged and tracked separately (dangling DNS candidates)

### CDN Detection

- [ ] **CDN-01**: User can check resolved IPs against CDN providers via cdncheck before port scanning
- [ ] **CDN-02**: CDN-hosted IPs are excluded from port scanning to avoid wasted effort
- [ ] **CDN-03**: User can see CDN provider identification in HTTP probe results (post-probe tagging)

### Port Scanning

- [ ] **PORT-01**: User can run fast port discovery via masscan on non-CDN IPs
- [ ] **PORT-02**: User can fingerprint discovered open ports via nmap for service/version identification
- [ ] **PORT-03**: Port scan results are associated with both IPs and their corresponding subdomains

### HTTP Probing

- [ ] **HTTP-01**: User can probe discovered hosts for HTTP/HTTPS services via httpx
- [ ] **HTTP-02**: HTTP probing runs against both raw IPs and subdomains to detect vhost-bound services
- [ ] **HTTP-03**: HTTP probing runs on all discovered open ports, not just 80/443
- [ ] **HTTP-04**: User can capture screenshots of live HTTP services via gowitness for visual triage

### Vulnerability Scanning

- [ ] **VULN-01**: User can run nuclei against discovered IPs and subdomains
- [ ] **VULN-02**: Vulnerability results include severity, affected host, and template ID
- [ ] **VULN-03**: User can filter nuclei templates by severity level

### Reporting

- [ ] **REPT-01**: Each pipeline stage produces a dedicated markdown report (subdomains.md, ports.md, http-probes.md, vulns.md, etc.)
- [ ] **REPT-02**: Reports are organized in per-target directories with timestamped scan folders
- [ ] **REPT-03**: A dangling DNS report lists all unresolved subdomains with CNAME records for subdomain takeover assessment
- [ ] **REPT-04**: Pipeline run produces structured log files for debugging and audit

### Scan Tracking

- [ ] **TRCK-01**: User can diff current scan against previous scan for the same target, highlighting new/removed subdomains, ports, and vulnerabilities
- [ ] **TRCK-02**: Scan history is stored per-target with timestamped entries
- [ ] **TRCK-03**: Dangling DNS records are tracked across scans to identify persistent vs. newly-appeared unresolved subdomains
- [ ] **TRCK-04**: Diff report highlights what changed in a human-readable markdown format

### Configuration & Safety

- [ ] **CONF-01**: User can configure tool parameters, rate limits, and stage settings via YAML config file
- [ ] **CONF-02**: CLI checks for required external tools on startup and reports which are missing with install instructions
- [ ] **CONF-03**: User can define scope boundaries (domain allowlist, CIDR ranges) that prevent scanning out-of-scope targets
- [ ] **CONF-04**: User can select from preset workflow templates (e.g., "bug bounty", "internal pentest", "quick recon")
- [ ] **CONF-05**: User can configure notification hooks (Slack/Discord/webhook) for scan completion events

## v2 Requirements

### Advanced Features

- **ADV-01**: Cost estimation before scan execution ("~2K hosts, ~4 hours estimated")
- **ADV-02**: Adaptive rate limiting that respects Retry-After headers and WAF detection
- **ADV-03**: Parallel stage execution for independent pipeline branches
- **ADV-04**: Integration with additional subdomain sources (amass, assetfinder, crt.sh)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Web GUI / Dashboard | Complexity explosion, pentesters live in terminal |
| Database storage (SQL/NoSQL) | Overkill for 2-person team, filesystem + bbolt sufficient |
| Built-in exploit modules | Legal risk, scope creep — stop at vulnerability identification |
| Custom subdomain bruteforcing | subfinder/amass are mature, don't reimplement |
| Active exploitation scanning | Dangerous, ethical issues, out of recon scope |
| Cloud-based results storage | Privacy/compliance risk for pentest data |
| Multi-user/team collaboration | 2-person team, share via git/filesystem |
| Mobile app | Pentesting is desktop/SSH workflow |
| Custom vulnerability scanner | Nuclei exists with community templates |
| Credential stuffing/brute force | Not reconnaissance, legal gray area |
| Social engineering modules | Different discipline entirely |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONF-01 | Phase 1 | Pending |
| CONF-02 | Phase 1 | Pending |
| DISC-01 | Phase 2 | Pending |
| DISC-02 | Phase 2 | Pending |
| DISC-03 | Phase 2 | Pending |
| DISC-04 | Phase 2 | Pending |
| DISC-05 | Phase 2 | Pending |
| PIPE-01 | Phase 2 | Pending |
| REPT-01 | Phase 2 | Pending |
| CDN-01 | Phase 3 | Pending |
| CDN-02 | Phase 3 | Pending |
| PORT-01 | Phase 3 | Pending |
| PORT-02 | Phase 3 | Pending |
| PORT-03 | Phase 3 | Pending |
| HTTP-01 | Phase 4 | Pending |
| HTTP-02 | Phase 4 | Pending |
| HTTP-03 | Phase 4 | Pending |
| HTTP-04 | Phase 4 | Pending |
| CDN-03 | Phase 4 | Pending |
| VULN-01 | Phase 5 | Pending |
| VULN-02 | Phase 5 | Pending |
| VULN-03 | Phase 5 | Pending |
| TRCK-01 | Phase 6 | Pending |
| TRCK-02 | Phase 6 | Pending |
| TRCK-03 | Phase 6 | Pending |
| TRCK-04 | Phase 6 | Pending |
| REPT-03 | Phase 6 | Pending |
| PIPE-02 | Phase 7 | Pending |
| PIPE-03 | Phase 7 | Pending |
| PIPE-04 | Phase 7 | Pending |
| PIPE-05 | Phase 7 | Pending |
| PIPE-06 | Phase 7 | Pending |
| PIPE-07 | Phase 7 | Pending |
| REPT-02 | Phase 7 | Pending |
| REPT-04 | Phase 7 | Pending |
| CONF-03 | Phase 7 | Pending |
| CONF-04 | Phase 7 | Pending |
| CONF-05 | Phase 7 | Pending |

**Coverage:**
- v1 requirements: 30 total
- Mapped to phases: 30
- Unmapped: 0

**Coverage verification:** ✓ All 30 v1 requirements mapped to phases

---
*Requirements defined: 2026-02-14*
*Last updated: 2026-02-14 after roadmap creation*
