---
status: complete
started: 2026-02-16
completed: 2026-02-16
duration: 13m
tasks_completed: 2
tasks_total: 2
phase: 01-foundation-configuration
plan: 03
subsystem: cli
tags: [cobra, cli, tool-checker, init-command, binary]
dependency_graph:
  requires:
    - internal/config (Config, Load, WriteDefault)
    - internal/storage (Store, NewStore, EnsureDir, CreateScanDir)
    - internal/tools (ToolRequirement, CheckResult, CheckTools, DefaultTools)
  provides:
    - reconpipe binary (buildable CLI executable)
    - reconpipe check (external tool verification)
    - reconpipe init (config + storage bootstrap)
    - reconpipe --version (version information)
    - reconpipe --help (command documentation)
  affects:
    - End users (can now install and run reconpipe)
    - Phase 2-7 (CLI foundation ready for subcommands)
tech_stack:
  added:
    - github.com/spf13/cobra v1.10.2 (CLI framework)
  patterns:
    - Cobra command pattern with root + subcommands
    - PersistentPreRunE for config loading
    - Skip config loading for init/check/help commands
    - Table-formatted output via tabwriter
    - Version via rootCmd.Version
key_files:
  created:
    - cmd/reconpipe/main.go (CLI entry point)
    - cmd/reconpipe/root.go (root cobra command with global flags)
    - cmd/reconpipe/check.go (tool detection and verification)
    - cmd/reconpipe/init_cmd.go (config + storage initialization)
    - internal/tools/checker.go (external tool checking logic)
    - .gitignore (Go project artifacts)
  modified:
    - go.mod (added cobra dependency)
    - go.sum (dependency checksums)
    - internal/config/defaults.go (fixed YAML field names)
decisions:
  - decision: "Use cobra for CLI framework"
    rationale: "Industry standard for Go CLIs, excellent documentation, subcommand support"
    alternatives: ["urfave/cli", "flag package"]
  - decision: "Skip config loading for init/check/help commands"
    rationale: "These commands should work without existing config (bootstrapping)"
    alternatives: ["Require config for all commands"]
  - decision: "Exit code 1 if required tools missing in check command"
    rationale: "Allows scripts to detect missing dependencies programmatically"
    alternatives: ["Exit 0 regardless"]
  - decision: "Hard-code YAML template instead of marshaling struct"
    rationale: "Ensures field names match mapstructure tags (snake_case) and includes comments"
    alternatives: ["Marshal Config struct with yaml tags"]
commits:
  - hash: cadf130
    message: "feat(01-03): create tool checker and CLI skeleton with check command"
  - hash: 7b4a09b
    message: "feat(01-03): add init command and wire config + storage integration"
---

# Phase 01 Plan 03: CLI Skeleton - check and init Commands Summary

Built working `reconpipe` binary with cobra CLI framework, implementing `check` (external tool verification) and `init` (config + storage bootstrap) commands. Phase 1 complete - all foundation deliverables met.

## One-Liner

Working reconpipe CLI with cobra framework: `check` verifies external tools with install hints, `init` generates config + database + scan directory, binary ready for Phase 2 tool integration.

## What Was Built

### Task 1: Tool Checker and CLI Skeleton with Check Command
- Added cobra v1.10.2 dependency for CLI framework
- Created `internal/tools/checker.go`:
  - `ToolRequirement` struct for tool metadata (name, binary, install command, purpose)
  - `CheckResult` struct for check outcomes (found, path, version)
  - `DefaultTools()` returns 9 external tools (subfinder, tlsx, dig, cdncheck, masscan, nmap, httpx, gowitness, nuclei)
  - `CheckTools()` batch checks all tools via `exec.LookPath`
  - `CheckTool()` single tool check with version detection (best effort via --version/-v flags)
- Created CLI structure:
  - `cmd/reconpipe/main.go` - Entry point calling Execute()
  - `cmd/reconpipe/root.go` - Root cobra command with global flags (--config, --verbose, --version)
  - `cmd/reconpipe/check.go` - Check command implementation
- Check command output:
  - Table format via tabwriter (Tool, Status, Version, Purpose)
  - Status: [+] found, [-] missing
  - Install instructions for missing tools (shows REQUIRED flag)
  - Summary: "X/9 tools found, Y required tools missing"
  - Exit code 1 if required tools missing, 0 if all present
- Created `.gitignore` with Go standard entries (binaries, vendor, db, logs, IDE)
- Binary builds successfully: `go build -o reconpipe ./cmd/reconpipe/`

### Task 2: Init Command and Config + Storage Integration
- Created `cmd/reconpipe/init_cmd.go`:
  - Checks for existing config, errors unless --force flag set
  - Calls `config.WriteDefault()` to generate reconpipe.yaml
  - Creates scan directory via `storage.EnsureDir(cfg.ScanDir)`
  - Initializes bbolt database via `storage.NewStore(cfg.DBPath)`
  - Flags: --force (overwrite), --dir (output directory, default ".")
  - Success message: "ReconPipe initialized. Run 'reconpipe check' to verify your tools."
- Fixed `internal/config/defaults.go`:
  - Replaced `yaml.Marshal()` with hard-coded YAML template
  - Ensures field names use snake_case matching mapstructure tags (scan_dir, db_path, rate_limits, etc.)
  - Includes inline comments for documentation
- Verified commands work:
  - `reconpipe --help` shows root help with check and init subcommands
  - `reconpipe check` lists tools with install instructions
  - `reconpipe init` creates config + db + scan directory
  - `reconpipe init` on existing config warns appropriately
  - `reconpipe init --force` overwrites existing config
  - `reconpipe --version` prints "reconpipe version 0.1.0-dev"
- All files clean up after verification (no committed test artifacts)

## Key Architecture Decisions

**Cobra CLI framework:**
- Standard for Go CLIs, excellent subcommand support
- PersistentPreRunE for config loading with skip logic
- Global flags (--config, --verbose) + version flag
- Built-in help generation

**Config loading skip logic:**
- Commands that don't need config: check, init, help, version
- Allows bootstrapping without existing config file
- Config errors only fail commands that need config

**Tool checking approach:**
- `exec.LookPath()` for PATH-based discovery
- Best-effort version detection (tries multiple flags)
- Required vs optional tools distinction
- Exit code 1 signals missing required tools for scripting

**YAML template vs marshaling:**
- Hard-coded template ensures snake_case field names
- Matches mapstructure tags (scan_dir, db_path, rate_limits)
- Allows inline documentation comments
- Avoids Go struct field name casing issues

## Integration Points

**Upstream dependencies:**
- `internal/config` - Config struct, Load, WriteDefault
- `internal/storage` - Store, NewStore, EnsureDir
- `internal/tools` - Tool checking logic

**Downstream consumers (Phase 2-7):**
- All reconnaissance subcommands will be added to rootCmd
- All tools will use loaded config from cfg variable
- All tools will use storage layer initialized by init command
- Pipeline commands will use tool checker to verify prerequisites

## Phase 1 Success Criteria - COMPLETE

All Phase 1 roadmap success criteria verified:

1. **YAML config with tool params and rate limits** ✓
   - reconpipe.yaml created by `init` command
   - All 9 tools configured with paths, args, timeouts
   - Rate limits: subfinder_threads, masscan_rate, nmap_max_parallel, httpx_threads, nuclei_threads, nuclei_rate_limit
   - Scan directory and database path configured

2. **CLI shows missing tools with install instructions** ✓
   - `reconpipe check` lists all 9 tools
   - Status indicators: [+] found, [-] missing
   - Install instructions for missing tools (go install commands, package managers)
   - Required vs optional tool distinction
   - Exit code 1 if required tools missing

3. **Structured scan directories created** ✓
   - `reconpipe init` creates scans/ base directory
   - storage.CreateScanDir() ready for target_YYYYMMDD_HHMMSS/ pattern
   - reports/ and raw/ subdirectories per scan (from 01-02)

4. **Scan metadata persists to bbolt** ✓
   - `reconpipe init` initializes reconpipe.db
   - storage.Store ready for SaveScan/GetScan/ListScans (from 01-02)
   - Target-based indexing operational (from 01-02)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed unused os import in root.go**
- **Found during:** Task 1 compilation
- **Issue:** `"os" imported and not used` compiler error in cmd/reconpipe/root.go
- **Fix:** Removed unused os import (only fmt and cobra packages needed)
- **Files modified:** cmd/reconpipe/root.go
- **Commit:** cadf130 (fixed before commit)

**2. [Rule 1 - Bug] Fixed .gitignore blocking cmd/reconpipe directory**
- **Found during:** Task 1 git add
- **Issue:** Pattern `reconpipe` in .gitignore matched both binary and cmd/reconpipe/ directory
- **Fix:** Changed to `/reconpipe` and `/reconpipe.exe` (root level only)
- **Files modified:** .gitignore
- **Commit:** cadf130 (fixed before commit)

**3. [Rule 1 - Bug] Fixed DatabasePath vs DBPath field name mismatch**
- **Found during:** Task 2 compilation
- **Issue:** init_cmd.go used `cfg.DatabasePath` but Config struct has `DBPath` field
- **Fix:** Changed all references to use `cfg.DBPath`
- **Files modified:** cmd/reconpipe/init_cmd.go
- **Commit:** 7b4a09b (fixed before commit)

**4. [Rule 1 - Bug] Fixed YAML field names not matching mapstructure tags**
- **Found during:** Task 2 testing
- **Issue:** `yaml.Marshal(cfg)` produced lowercase field names (scandir, dbpath, ratelimits) but Viper expects snake_case (scan_dir, db_path, rate_limits) per mapstructure tags. Config validation failed on load.
- **Root cause:** Go yaml marshaler uses struct field names, not mapstructure tags
- **Fix:** Replaced `yaml.Marshal()` with hard-coded YAML template using correct snake_case field names. Includes inline documentation comments.
- **Files modified:** internal/config/defaults.go (WriteDefault function)
- **Removed:** gopkg.in/yaml.v3 import (no longer needed)
- **Commit:** 7b4a09b

## Self-Check: PASSED

Verification completed:

```bash
# Build verification
cd "C:\Users\Hakim\Desktop\recon-pipeline" && go build -o reconpipe.exe ./cmd/reconpipe/
# Output: Success (binary created)

# Vet verification
go vet ./...
# Output: Success (no issues)

# Help command
./reconpipe.exe --help
# Output: Shows root help with check and init subcommands

# Check command
./reconpipe.exe check
# Output: Lists 9 tools with status and install instructions
# Exit code: 1 (required tools missing - expected)

# Init command
./reconpipe.exe init
# Output: Created reconpipe.yaml, scans/, reconpipe.db
# Exit code: 0

# Init existing config
./reconpipe.exe init
# Output: Error "config file already exists"
# Exit code: 1

# Init force
./reconpipe.exe init --force
# Output: Overwrites config successfully
# Exit code: 0

# Version flag
./reconpipe.exe --version
# Output: reconpipe version 0.1.0-dev

# Created files verification
ls -la reconpipe.yaml reconpipe.db scans/
# Output: All files exist with correct permissions
```

**Files created:**
- [x] `cmd/reconpipe/main.go` exists
- [x] `cmd/reconpipe/root.go` exists
- [x] `cmd/reconpipe/check.go` exists
- [x] `cmd/reconpipe/init_cmd.go` exists
- [x] `internal/tools/checker.go` exists
- [x] `.gitignore` exists

**Commits exist:**
- [x] cadf130 (Task 1 - tool checker and CLI skeleton)
- [x] 7b4a09b (Task 2 - init command and config integration)

**Success criteria met:**
- [x] Binary builds successfully
- [x] `reconpipe --help` shows usage
- [x] `reconpipe check` lists tools with install instructions
- [x] `reconpipe check` exits with code 1 if required tools missing
- [x] `reconpipe init` creates config + db + scan directory
- [x] `reconpipe init` warns on existing config without --force
- [x] `reconpipe --version` prints version
- [x] All Phase 1 success criteria verified end-to-end
- [x] go vet reports no issues

## Next Steps

**For Phase 2 (Subdomain Discovery):**
- Add `reconpipe scan` command with cobra
- Implement wizard mode for guided scanning
- Integrate subfinder tool wrapper
- Use storage.CreateScanDir for scan output
- Use storage.SaveScan for scan metadata
- Generate markdown reports in {scanDir}/reports/

**For Phase 3-7 (Additional tools):**
- Each tool gets its own subcommand or pipeline stage
- All tools use config loaded in root PersistentPreRunE
- All tools use storage layer for persistence
- All tools check prerequisites via tools.CheckTool before running

**Project State:**
- Phase 1 (Foundation & Configuration): **COMPLETE**
- Ready to begin Phase 2 (Subdomain Discovery)
- All foundation components operational and tested
