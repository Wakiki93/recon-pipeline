---
phase: 02-subdomain-discovery
plan: 01
subsystem: discovery
tags: [subfinder, tlsx, dig, dns, subdomain-enumeration, go]

# Dependency graph
requires:
  - phase: 01-foundation-configuration
    provides: models.Subdomain, models.DNSRecord, models.DNSRecordType, config.ToolConfig
provides:
  - Shared subprocess runner (RunTool) with deadlock-safe concurrent pipe reading
  - Tool wrappers for subfinder, tlsx, and dig with JSON parsing
  - Discovery pipeline orchestrating enumeration, deduplication, and DNS resolution
  - Dangling DNS classification (high-priority CNAME vs low-priority stale)
affects: [02-subdomain-discovery-02, 03-subdomain-http-probing, reporting]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Concurrent stdout/stderr reading via goroutines to prevent subprocess deadlocks"
    - "JSONL parsing with error tolerance (skip malformed lines, log warnings)"
    - "Sequential DNS resolution with CNAME fallback for dangling detection"
    - "Case-insensitive deduplication with trailing-dot stripping"

key-files:
  created:
    - internal/tools/runner.go
    - internal/tools/subfinder.go
    - internal/tools/tlsx.go
    - internal/tools/dig.go
    - internal/discovery/pipeline.go
    - internal/discovery/dns.go
  modified: []

key-decisions:
  - "Use map[string]string for deduplication instead of unique package (simpler, tracks source)"
  - "Sequential DNS resolution (concurrent optimization deferred to Phase 6+)"
  - "Individual dig calls per subdomain (simpler parsing vs batch -f mode)"
  - "Two-stage dangling DNS: high-priority = unresolved + CNAME, low-priority = unresolved only"

patterns-established:
  - "Tool wrappers accept binaryPath parameter with fallback to tool name"
  - "RunTool sets WaitDelay=5s for subprocess cleanup after context cancellation"
  - "Scanner-based stdout reading for line-oriented tools, io.Copy for stderr"
  - "Normalization: lowercase + TrimSpace + TrimSuffix('.') + wildcard filtering"

# Metrics
duration: 6min
completed: 2026-02-16
---

# Phase 02 Plan 01: Discovery Engine Summary

**Subdomain discovery engine with subfinder/tlsx/dig wrappers, case-insensitive deduplication, DNS resolution, and CNAME-based dangling DNS classification**

## Performance

- **Duration:** 6 min 19 sec
- **Started:** 2026-02-16T23:15:54Z
- **Completed:** 2026-02-16T23:22:13Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Tool wrappers for subfinder, tlsx, and dig with robust JSONL parsing
- Shared subprocess runner preventing stdout/stderr buffer deadlocks
- Discovery pipeline orchestrating enumeration with normalization and deduplication
- DNS resolution with CNAME-based dangling DNS classification (high vs low priority)

## Task Commits

Each task was committed atomically:

1. **Task 1: Tool wrappers — subfinder, tlsx, dig, and shared runner** - `ac528a2` (feat)
   - Created internal/tools/runner.go with RunTool deadlock-safe subprocess execution
   - Created internal/tools/subfinder.go parsing JSONL with source attribution
   - Created internal/tools/tlsx.go extracting SAN/CN with wildcard filtering
   - Created internal/tools/dig.go with ResolveSubdomains and CheckCNAME

2. **Task 2: Discovery pipeline — orchestration, deduplication, and dangling DNS classification** - `18a78b1` (feat)
   - Created internal/discovery/pipeline.go with RunDiscovery orchestration
   - Created internal/discovery/dns.go with ResolveBatch and ClassifyDangling
   - Deduplication via map with normalization (lowercase, trailing dot strip)
   - High-priority dangling = unresolved + CNAME, low-priority = unresolved only

## Files Created/Modified

**Created:**
- `internal/tools/runner.go` - Shared subprocess executor with concurrent pipe reading and context timeout enforcement
- `internal/tools/subfinder.go` - Subfinder wrapper returning parsed SubfinderResult with source attribution
- `internal/tools/tlsx.go` - tlsx wrapper extracting certificate SAN/CN entries with wildcard/out-of-scope filtering
- `internal/tools/dig.go` - dig wrapper for A/AAAA resolution and CNAME lookup
- `internal/discovery/pipeline.go` - Discovery orchestration running subfinder+tlsx, deduplicating, and resolving DNS
- `internal/discovery/dns.go` - DNS resolution batch processor with dangling DNS classification

**Modified:**
- None

## Decisions Made

1. **Map-based deduplication over unique package** - Using `map[string]string` (key=normalized subdomain, value=source) is simpler and already tracks source attribution needed for reporting. The unique package would require separate source tracking.

2. **Sequential DNS resolution** - Kept DNS resolution sequential for simplicity. Concurrent resolution can be added in Phase 6+ when performance profiling shows it's needed. Typical subdomain counts (hundreds to low thousands) don't justify premature optimization.

3. **Individual dig calls** - Using separate dig invocations per subdomain instead of batch `-f` mode simplifies parsing and error handling. Each subdomain gets independent error handling without batch-level failure cascades.

4. **Two-stage dangling DNS classification** - Unresolved subdomains with CNAME records = high priority (subdomain takeover candidates). Unresolved without CNAME = low priority (stale DNS cleanup). This distinction guides remediation priority.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all tools compiled cleanly on first attempt after correcting module import paths from `recon-pipeline` to `github.com/hakim/reconpipe` per go.mod.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

**Ready for Phase 02 Plan 02 (CLI command integration):**
- Discovery pipeline `RunDiscovery()` ready to be called from CLI command
- `DiscoveryResult` struct has all fields needed for report generation
- Tool wrappers accept binary paths from config.ToolsConfig
- Dangling DNS classification available via `ClassifyDangling()` for report sections

**No blockers** - all dependencies satisfied, all verification passed.

## Self-Check: PASSED

All files verified:
- internal/tools/runner.go: FOUND
- internal/tools/subfinder.go: FOUND
- internal/tools/tlsx.go: FOUND
- internal/tools/dig.go: FOUND
- internal/discovery/pipeline.go: FOUND
- internal/discovery/dns.go: FOUND

All commits verified:
- ac528a2: FOUND
- 18a78b1: FOUND

---
*Phase: 02-subdomain-discovery*
*Completed: 2026-02-16*
