---
phase: 02-subdomain-discovery
plan: 02
subsystem: cli-report
tags: [cli, cobra, markdown, report-generation, go]

# Dependency graph
requires:
  - phase: 02-subdomain-discovery-01
    provides: discovery.RunDiscovery, discovery.DiscoveryResult, discovery.ClassifyDangling
  - phase: 01-foundation-configuration
    provides: models.Scan, models.ScanMeta, storage.CreateScanDir, storage.SaveScan, config.Config
provides:
  - User-facing discover command (reconpipe discover -d <domain>)
  - Markdown report generation for subdomain discovery results
  - End-to-end subdomain discovery workflow (CLI -> pipeline -> report)
affects: [03-subdomain-http-probing, reporting, user-workflow]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Markdown report generation with strings.Builder for performance"
    - "Graceful optional tool handling (warn and auto-skip if missing)"
    - "Pre-flight tool verification before pipeline execution"
    - "Dual output format: human-readable markdown + machine-readable JSON"
    - "Progress output at key pipeline stages"

key-files:
  created:
    - internal/report/markdown.go
    - cmd/reconpipe/discover.go
  modified: []

key-decisions:
  - "Use strings.Builder for report generation (efficient string concatenation)"
  - "Separate high-priority vs low-priority dangling DNS in report sections (guides remediation)"
  - "Write both markdown report and raw JSON (human + machine consumption)"
  - "Auto-skip tlsx if missing instead of failing (optional discovery source)"
  - "Pre-flight tool check prevents partial execution (fail fast with helpful errors)"

patterns-established:
  - "Report sections: summary stats, sources, resolved, high-priority dangling, low-priority dangling, unresolved"
  - "Empty sections show 'None found' instead of blank tables"
  - "CLI commands check required tools before execution"
  - "Scan metadata persisted before pipeline execution, updated after completion"
  - "Error handling: update scan status to Failed before returning errors"

# Metrics
duration: 9min
completed: 2026-02-16
---

# Phase 02 Plan 02: CLI Command & Report Generation Summary

**User-facing discover command with markdown report generation for subdomain discovery pipeline**

## Performance

- **Duration:** 9 min 9 sec
- **Started:** 2026-02-16T23:26:50Z
- **Completed:** 2026-02-16T23:35:59Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Markdown report generator with structured sections for resolved/dangling/unresolved subdomains
- Discover CLI command wiring pipeline execution, storage persistence, and report generation
- Pre-flight tool checking with helpful error messages for missing dependencies
- Dual output format: markdown for humans, JSON for machines
- Complete subdomain discovery workflow accessible via single command

## Task Commits

Each task was committed atomically:

1. **Task 1: Markdown report generator for subdomain discovery** - `55c8188` (feat)
   - Created internal/report/markdown.go with WriteSubdomainReport function
   - Report sections: summary stats, source breakdown, resolved subdomains, dangling DNS (high/low priority), unresolved
   - Uses strings.Builder for efficient string concatenation
   - Handles empty sections gracefully with "None found" messages
   - Classifies dangling DNS using discovery.ClassifyDangling for CNAME takeover candidates vs stale DNS

2. **Task 2: Cobra discover command - wire pipeline + storage + report** - `a872a0a` (feat)
   - Created cmd/reconpipe/discover.go wiring discovery pipeline to CLI
   - Pre-flight check: verifies subfinder and dig are available before running
   - Handles tlsx gracefully (warns and auto-skips if missing)
   - Creates scan directory and saves metadata to bbolt database
   - Runs discovery pipeline with configurable timeout (default 10m)
   - Writes markdown report to {scanDir}/reports/subdomains.md
   - Saves raw JSON output to {scanDir}/raw/subdomains.json
   - Updates scan status (running -> complete/failed) with error handling
   - Progress output: starting, tool execution, completion summary
   - Command flags: -d/--domain (required), --skip-tlsx, --timeout

## Files Created/Modified

**Created:**
- `internal/report/markdown.go` - Markdown report generator with WriteSubdomainReport, formats discovery results into structured markdown with summary stats, source breakdown, resolved subdomains table, high-priority dangling DNS (CNAME takeover candidates), low-priority dangling DNS (stale DNS), and unresolved entries
- `cmd/reconpipe/discover.go` - Cobra discover command implementing full workflow: tool verification, scan directory creation, database persistence, pipeline execution, report generation, and status tracking with progress output and error handling

**Modified:**
- None

## Decisions Made

1. **strings.Builder for report generation** - Using strings.Builder for efficient string concatenation when building markdown report. Avoids repeated string allocations during report construction. Standard Go pattern for building large strings.

2. **Separate high-priority vs low-priority dangling DNS sections** - Report splits dangling DNS into two sections: high-priority (unresolved with CNAME = takeover candidates) and low-priority (unresolved without CNAME = stale DNS). This separation guides remediation priority and makes actionable items clear.

3. **Dual output format (markdown + JSON)** - Write both markdown report (human-readable) and raw JSON (machine-readable). Markdown for immediate review, JSON for programmatic consumption, diffing, or future processing.

4. **Auto-skip tlsx if missing** - If tlsx is not installed and --skip-tlsx is not set, print warning and auto-skip instead of failing. tlsx is an optional discovery source (supplements subfinder), so its absence shouldn't block the entire pipeline.

5. **Pre-flight tool check** - Verify required tools (subfinder, dig) are available before starting pipeline execution. Fail fast with helpful install instructions instead of failing mid-execution with cryptic errors.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

**Issue 1: Field name mismatch between plan and models**

- **Found during:** Task 1 compilation
- **Issue:** Plan specified fields like `sub.Hostname`, `sub.DNS`, `sub.DiscoverySource` but models.Subdomain has `Name`, `DNSRecords`, `Source`
- **Fix:** Updated all field references in markdown.go to match actual model structure
- **Classification:** Not a deviation - simple code correction during implementation

**Issue 2: DNSRecordType constant names**

- **Found during:** Task 1 compilation
- **Issue:** Used `models.DNSRecordTypeA` but constant is `models.DNSRecordA` (without "Type" suffix)
- **Fix:** Updated constant references to match models/types.go definitions
- **Classification:** Not a deviation - simple code correction during implementation

**Issue 3: Go not in PATH**

- **Found during:** Task 1 verification
- **Issue:** `go` command not found in bash PATH (Windows MINGW environment)
- **Fix:** Used full path `/c/Program Files/Go/bin/go.exe` for all Go commands
- **Classification:** Environment issue, not a code deviation

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

**Phase 02 Complete - Ready for Phase 03 (HTTP Probing):**
- Discover command produces subdomains.md report in scan directory
- Raw JSON output available for machine consumption
- Subdomain data persisted to database with scan metadata
- Resolved subdomains ready for HTTP probing pipeline
- Dangling DNS candidates identified for remediation

**No blockers** - all verification passed, full subdomain discovery workflow functional.

## Self-Check: PASSED

All files verified:
- internal/report/markdown.go: FOUND
- cmd/reconpipe/discover.go: FOUND

All commits verified:
- 55c8188: FOUND
- a872a0a: FOUND

Build verification:
- `go build ./...`: SUCCESS
- `go vet ./...`: SUCCESS
- Binary created: reconpipe.exe
- Command help: WORKS (shows -d flag as required)

---
*Phase: 02-subdomain-discovery*
*Completed: 2026-02-16*
