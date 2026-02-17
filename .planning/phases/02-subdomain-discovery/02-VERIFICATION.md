---
phase: 02-subdomain-discovery
verified: 2026-02-16T23:50:00Z
status: gaps_found
score: 9/10
re_verification: false
gaps:
  - truth: "Report shows resolved subdomains with IPs, dangling DNS candidates with CNAME targets, and summary statistics"
    status: failed
    reason: "Markdown report cannot display resolved subdomains - data model mismatch between dns.go and markdown.go"
    artifacts:
      - path: "internal/report/markdown.go"
        issue: "getResolvedSubdomains() checks DNSRecords for A/AAAA records, but dns.go stores IPs in sub.IPs field"
      - path: "internal/discovery/dns.go"
        issue: "ResolveBatch stores IPs in sub.IPs but never populates DNSRecords with A/AAAA records"
    missing:
      - "Update dns.go to populate DNSRecords with A/AAAA records when storing IPs"
      - "OR update markdown.go to use sub.Resolved and sub.IPs instead of checking DNSRecords"
---

# Phase 2: Subdomain Discovery Verification Report

**Phase Goal:** Implement subdomain enumeration using subfinder + tlsx with certificate analysis, DNS resolution to validate live hosts, and dangling DNS detection for potential takeover targets.

**Verified:** 2026-02-16T23:50:00Z
**Status:** gaps_found
**Re-verification:** No - initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | subfinder wrapper executes with JSON output and returns parsed subdomain results | VERIFIED | internal/tools/subfinder.go exports RunSubfinder, parses JSONL with source attribution, used by pipeline.go line 46 |
| 2 | tlsx wrapper executes with JSON output and extracts SAN/CN entries | VERIFIED | internal/tools/tlsx.go exports RunTlsx, filters wildcards and out-of-scope entries, used by pipeline.go line 70 |
| 3 | dig wrapper resolves subdomains to IPs and detects NXDOMAIN vs SERVFAIL | VERIFIED | internal/tools/dig.go exports ResolveSubdomains and CheckCNAME, parses dig +short output, used by dns.go lines 19 and 36 |
| 4 | Subdomains from subfinder and tlsx are deduplicated (case-insensitive, trailing dot stripped, wildcards filtered) | VERIFIED | pipeline.go normalizeSubdomain() function (lines 134-150) handles lowercase, TrimSpace, TrimSuffix('.'), wildcard filtering; map-based dedup on line 42 |
| 5 | Unresolved subdomains with CNAME records are flagged as HIGH priority dangling DNS candidates | VERIFIED | dns.go ResolveBatch sets IsDangling=true and adds CNAME to DNSRecords (lines 44-52); ClassifyDangling separates high/low priority (lines 64-86); used in markdown.go line 54 |
| 6 | User can run 'reconpipe discover -d example.com' to discover subdomains | VERIFIED | cmd/reconpipe/discover.go exports discoverCmd, flag validation works (tested), wired to rootCmd on line 174 |
| 7 | Command creates scan directory, saves scan metadata to bbolt, runs discovery pipeline | VERIFIED | discover.go creates scan dir (line 73), saves metadata (line 88), runs RunDiscovery (line 110), updates status (lines 113, 148) |
| 8 | Pipeline produces subdomains.md report in the scan's reports/ directory | VERIFIED | discover.go writes report via WriteSubdomainReport (line 123) to {scanDir}/reports/subdomains.md |
| 9 | Report shows resolved subdomains with IPs, dangling DNS candidates with CNAME targets, and summary statistics | FAILED | markdown.go getResolvedSubdomains() checks DNSRecords for A/AAAA records (line 109), but dns.go stores IPs in sub.IPs field (line 33), not DNSRecords - resolved subdomains will NOT appear in report |
| 10 | Command outputs progress to terminal (starting, tool running, complete) and final summary | VERIFIED | discover.go has progress output: lines 93-94 (starting), 118-119 (summary), 127 (report written), 154-158 (final summary) |

**Score:** 9/10 truths verified (1 failed due to data model mismatch)


### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| internal/tools/runner.go | Shared subprocess execution with concurrent pipe reading and context timeout | VERIFIED | Exports RunTool and ToolResult; uses goroutines for stdout/stderr (lines 53-66); sets WaitDelay=5s (line 27) |
| internal/tools/subfinder.go | Subfinder wrapper returning parsed subdomains | VERIFIED | Exports RunSubfinder and SubfinderResult; JSONL parsing with error tolerance (lines 48-65); thread flag support (lines 37-39) |
| internal/tools/tlsx.go | tlsx wrapper returning parsed subdomains from certificate SAN/CN | VERIFIED | Exports RunTlsx and TlsxResult; extracts SubjectCN and SubjectAN (lines 62-73); wildcard/scope filtering via isValidSubdomain (lines 91-103) |
| internal/tools/dig.go | dig wrapper for A/AAAA resolution and CNAME lookup | VERIFIED | Exports ResolveSubdomains, CheckCNAME, and DNSResult; parses dig +short output (lines 47-63); CNAME extraction (lines 96-102) |
| internal/discovery/pipeline.go | Discovery orchestration: run subfinder+tlsx, deduplicate, resolve | VERIFIED | Exports RunDiscovery and DiscoveryResult; orchestrates subfinder (line 46), tlsx (line 70), deduplication via map (line 42), DNS resolution (line 109) |
| internal/discovery/dns.go | DNS resolution and dangling DNS classification | VERIFIED | Exports ResolveBatch and ClassifyDangling; resolves DNS (line 19), checks CNAME (line 36), sets IsDangling (line 44), classifies by CNAME presence (lines 64-86) |
| internal/report/markdown.go | Markdown report generation for subdomain discovery results | ORPHANED | Exports WriteSubdomainReport; substantive implementation with all sections; WIRED to discover.go line 123; BUT has data model mismatch - checks DNSRecords instead of sub.IPs/sub.Resolved |
| cmd/reconpipe/discover.go | Cobra discover command wiring pipeline + storage + report | VERIFIED | Exports discoverCmd; all 16 workflow steps implemented; pre-flight check (lines 40-53), pipeline execution (line 110), report writing (line 123), status tracking (lines 88, 113, 148) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| internal/tools/subfinder.go | internal/tools/runner.go | RunTool for subprocess execution | WIRED | subfinder.go line 42 calls RunTool |
| internal/tools/tlsx.go | internal/tools/runner.go | RunTool for subprocess execution | WIRED | tlsx.go line 39 calls RunTool |
| internal/discovery/pipeline.go | internal/tools/subfinder.go | RunSubfinder call | WIRED | pipeline.go line 46: tools.RunSubfinder() |
| internal/discovery/pipeline.go | internal/tools/tlsx.go | RunTlsx call | WIRED | pipeline.go line 70: tools.RunTlsx() |
| internal/discovery/pipeline.go | internal/discovery/dns.go | ResolveBatch for DNS resolution | WIRED | pipeline.go line 109 calls ResolveBatch |
| internal/discovery/dns.go | internal/tools/dig.go | dig wrapper for resolution and CNAME checks | WIRED | dns.go line 19 calls tools.ResolveSubdomains, line 36 calls tools.CheckCNAME |
| cmd/reconpipe/discover.go | internal/discovery/pipeline.go | RunDiscovery call | WIRED | discover.go line 110: discovery.RunDiscovery() |
| cmd/reconpipe/discover.go | internal/storage | SaveScan and UpdateScanStatus for metadata persistence | WIRED | discover.go lines 88, 143 (SaveScan), lines 113, 148 (UpdateScanStatus) |
| cmd/reconpipe/discover.go | internal/report/markdown.go | WriteSubdomainReport to generate report file | WIRED | discover.go line 123: report.WriteSubdomainReport() |
| cmd/reconpipe/discover.go | internal/tools/checker.go | CheckTool to verify subfinder/dig available before running | WIRED | discover.go lines 49, 56: tools.CheckTool() |

### Requirements Coverage

Phase 2 addresses requirements: DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, PIPE-01 (basic), REPT-01 (basic)

| Requirement | Status | Blocking Issue |
|-------------|--------|----------------|
| DISC-01: Subfinder integration | SATISFIED | All supporting truths verified |
| DISC-02: TLS certificate analysis | SATISFIED | All supporting truths verified |
| DISC-03: DNS resolution | SATISFIED | All supporting truths verified |
| DISC-04: Deduplication | SATISFIED | All supporting truths verified |
| DISC-05: Dangling DNS detection | SATISFIED | Classification works, CNAME detection works |
| PIPE-01: Basic pipeline orchestration | SATISFIED | Pipeline runs end-to-end |
| REPT-01: Basic markdown reporting | BLOCKED | Report generates but cannot display resolved subdomains due to data model mismatch |


### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| internal/discovery/dns.go | 33 | Data stored in sub.IPs but report expects DNSRecords | Blocker | Resolved subdomains will not appear in markdown report "Resolved Subdomains" section |
| internal/report/markdown.go | 109 | hasIPRecords() checks DNSRecords instead of sub.Resolved flag | Blocker | Function always returns false because DNSRecords never populated with A/AAAA records |
| internal/report/markdown.go | 138-149 | formatIPs() extracts from DNSRecords instead of sub.IPs | Blocker | Will always return "-" for IPs because DNSRecords is empty |

**Root cause:** dns.go and markdown.go use different data access patterns for the same information. The Subdomain model has two ways to represent IP resolution:
1. sub.Resolved bool + sub.IPs []string (used by dns.go)
2. sub.DNSRecords []DNSRecord with A/AAAA records (expected by markdown.go)

Only approach #1 is populated, but markdown.go expects approach #2.

### Gaps Summary

**1 critical gap blocking goal achievement:**

The markdown report cannot display resolved subdomains due to a data model mismatch. The DNS resolution code (internal/discovery/dns.go) stores IP addresses in the sub.IPs field and sets sub.Resolved = true, but the markdown report generator (internal/report/markdown.go) checks for A/AAAA records in the sub.DNSRecords array to determine which subdomains are resolved.

**Impact:**
- "Resolved Subdomains" section will always show "None found" even when subdomains resolve
- IP addresses will not appear in the report (formatIPs always returns "-")
- User cannot see which subdomains successfully resolved to IP addresses
- Report is missing its primary value - showing live, resolved targets

**Fix options:**
1. Update dns.go to populate DNSRecords with A/AAAA records when storing IPs
2. Update markdown.go to check sub.Resolved and use sub.IPs directly instead of checking DNSRecords

**All other aspects verified successfully:**
- Tool wrappers work correctly (subfinder, tlsx, dig)
- Deduplication logic handles normalization properly
- Dangling DNS classification works (high/low priority split)
- CLI command wired correctly with pre-flight checks
- Scan metadata persisted to database
- Progress output shown during execution
- All commits exist in git history

---

_Verified: 2026-02-16T23:50:00Z_
_Verifier: Claude (gsd-verifier)_
