# Domain Pitfalls: Recon Pipeline Orchestration

**Domain:** Security tool orchestration / Recon automation
**Researched:** 2026-02-14
**Confidence:** MEDIUM (based on training data, security tooling patterns, Go process management best practices)

**Note:** Web research tools unavailable. Findings based on established patterns in security tool orchestration, Go CLI development, and process management. Key claims should be validated against current ProjectDiscovery documentation and community reports.

---

## Critical Pitfalls

Mistakes that cause data loss, production failures, or major rewrites.

### Pitfall 1: Zombie Process Accumulation
**What goes wrong:** External tools (nmap, masscan, subfinder) spawn child processes that don't terminate when parent dies. Over time, hundreds of zombie processes accumulate, exhausting system resources.

**Why it happens:**
- Go's `exec.Command()` doesn't automatically kill child processes on context cancellation
- Tools like nmap spawn multiple child processes for parallel scanning
- Ctrl+C or timeout kills parent but not children
- No process group management

**Consequences:**
- System resource exhaustion (PIDs, memory, CPU)
- "Cannot fork" errors on subsequent runs
- Requires manual `killall` or system restart
- Lost scan data when forced to kill processes

**Prevention:**
```go
// Set process group ID for coordinated cleanup
cmd.SysProcAttr = &syscall.SysProcAttr{
    Setpgid: true,
}

// Kill entire process group on context cancel
defer func() {
    if cmd.Process != nil {
        syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
    }
}()
```

**Detection:**
- `ps aux | grep [tool]` shows orphaned processes after pipeline exits
- Memory usage climbs across multiple runs
- Tools hang on startup (PID exhaustion)

**Phase impact:** Foundation phase must include robust process lifecycle management. Retrofitting is painful.

---

### Pitfall 2: Output Parser Brittleness
**What goes wrong:** Tools change output format in minor versions. Pipeline breaks silently, reporting zero findings instead of parsing errors.

**Why it happens:**
- Security tools don't guarantee stable output schemas (nuclei, nmap constantly evolve)
- Regex-based parsing fragile to whitespace/format changes
- Tools mix structured output (JSON) with human-readable progress on stderr
- No validation that parsed output makes sense

**Consequences:**
- Silent data loss (zero findings reported when parsing fails)
- False confidence in "clean" scans that actually failed
- Hours debugging why tool "stopped working" (it didn't, parser broke)
- Emergency fixes when tools auto-update

**Prevention:**
- **Use JSON output modes exclusively** (`-json`, `-oJ`, `-jsonl`)
- Validate parsed output (empty result = suspicious, log warning)
- Version-pin external tools in documentation
- Include raw output preservation (for manual inspection when parser fails)
- Fail loudly on parse errors (don't return empty slice silently)

```go
// BAD: Silent failure
results := parseOutput(output)
return results // empty slice on parse error

// GOOD: Fail loudly
results, err := parseOutput(output)
if err != nil {
    return fmt.Errorf("parse failed (tool version mismatch?): %w", err)
}
if len(results) == 0 && !isEmpty(output) {
    log.Warn("Parsed zero results from non-empty output - parser may be broken")
}
```

**Detection:**
- Sudden drop to zero findings after tool updates
- Manual tool run shows results, but pipeline reports none
- Non-empty raw output files with empty parsed results

**Phase impact:** Data model phase must standardize on JSON parsing with validation. Ad-hoc parsers create technical debt.

---

### Pitfall 3: Rate Limiting Cascade Failures
**What goes wrong:** Pipeline hammers APIs (Shodan, VirusTotal, DNS resolvers) without backoff. Gets IP banned mid-scan. Subsequent stages fail because they depend on banned APIs.

**Why it happens:**
- Each tool manages its own rate limiting (or doesn't)
- Pipeline doesn't track cumulative API usage across tools
- Subfinder hits 10 APIs in parallel, each with different limits
- No central rate limit coordination
- Retries amplify the problem (exponential API calls on failures)

**Consequences:**
- IP/API key bans (24h-30d lockouts)
- Incomplete scan data (half the subdomains found, then banned)
- Wasted compute (later pipeline stages run on incomplete data)
- Can't re-run without VPN/proxy rotation

**Prevention:**
- Expose rate limit controls at pipeline level (not just per-tool)
- Respect API key tier limits (track cumulative usage)
- Implement exponential backoff with jitter
- Fail fast on rate limit errors (don't continue pipeline with partial data)
- Document which tools require API keys and their limits

```go
type RateLimiter struct {
    providers map[string]*rate.Limiter // per-API limits
    globalLimit *rate.Limiter           // overall cap
}

// Before calling subfinder/nuclei/etc
if !rl.Allow(tool, provider) {
    return ErrRateLimited // halt pipeline, don't continue with partial data
}
```

**Detection:**
- 429 HTTP errors in tool output
- Sudden drop in results mid-pipeline
- "No results found" for known-good targets
- API providers sending warning emails

**Phase impact:** Should be in initial implementation. Retrofitting rate limiting across multiple tools is complex.

---

### Pitfall 4: Output File Chaos
**What goes wrong:** Tool outputs scattered across temp directories, inconsistent naming, orphaned on crashes. Can't correlate subfinder output with nmap results. Lost data on re-runs.

**Why it happens:**
- Each tool has different default output paths
- No standardized naming convention (timestamp? target? stage?)
- Temp files not cleaned up on errors
- Overwriting previous scans instead of versioning
- No manifest tracking which files belong to which scan

**Consequences:**
- Manual file hunting to correlate results
- Disk space exhaustion from temp file accumulation
- Can't diff scans (no stable output paths)
- Lost data when re-running overwrites previous results

**Prevention:**
- Structured output directory per scan:
  ```
  scans/
    example.com_2026-02-14_15-30/
      01-subfinder.json
      02-tlsx.json
      03-masscan.json
      04-nmap.json
      05-httpx.json
      06-nuclei.json
      manifest.json (metadata)
  ```
- Atomic writes (write to `.tmp`, rename on success)
- Cleanup temp files in defer blocks
- Track all output paths in manifest for correlation

**Detection:**
- Growing `/tmp` directory over time
- Can't find output from previous scans
- "File not found" errors in later stages
- Inconsistent results when re-running same target

**Phase impact:** Core implementation phase. Output structure is foundational.

---

### Pitfall 5: Cross-Platform Path Assumptions
**What goes wrong:** Hardcoded `/tmp`, `/usr/bin`, Unix-style paths. Tool breaks on Windows/WSL with cryptic errors.

**Why it happens:**
- Developers test on Linux, forget Windows exists
- WSL path translation (`/mnt/c/` vs `C:\`) inconsistencies
- External tools installed in different locations per platform
- Assuming `sh` is available for shell commands

**Consequences:**
- "Tool not found" on Windows when installed correctly
- Path separator errors (`/` vs `\`)
- Temp file creation fails (wrong directory structure)
- Can't share configs between Linux/macOS/WSL users

**Prevention:**
- Use `os.TempDir()`, never hardcode `/tmp`
- Use `filepath.Join()` for all path construction
- Use `exec.LookPath()` to find tools in PATH (don't hardcode `/usr/bin/nmap`)
- Test on Windows, macOS, Linux (not just your dev platform)
- Document platform-specific installation steps

```go
// BAD
cmd := exec.Command("/usr/bin/nmap", "-oJ", "/tmp/scan.json")

// GOOD
nmapPath, err := exec.LookPath("nmap")
if err != nil {
    return fmt.Errorf("nmap not found in PATH: %w", err)
}
outFile := filepath.Join(os.TempDir(), "reconpipe", "scan.json")
cmd := exec.Command(nmapPath, "-oJ", outFile)
```

**Detection:**
- Works on dev machine, fails on collaborator's (different OS)
- "No such file or directory" errors with Unix paths
- Tool installed but "not found"

**Phase impact:** Should be in foundation. Retrofitting path handling is tedious.

---

### Pitfall 6: Timeout Mismanagement
**What goes wrong:** Long-running scans (nmap on large networks) hit arbitrary timeout and die mid-scan. Or: no timeouts, hung tool blocks pipeline forever.

**Why it happens:**
- One-size-fits-all timeout (30s for subfinder, 30s for nmap on /16 network)
- No progress monitoring (can't tell if tool is hung or working)
- Context cancellation doesn't actually stop external process (see Pitfall 1)
- No way to extend timeout for large targets

**Consequences:**
- Incomplete scans (nmap killed after 100 of 10,000 ports)
- Hung pipelines requiring manual kill
- Can't scan large networks (always timeout)
- Wasted compute (kill scan at 90% completion)

**Prevention:**
- Per-tool configurable timeouts (subfinder: 5m, nmap: 1h, nuclei: 30m)
- Progress monitoring (parse tool output for progress indicators)
- Graceful shutdown (SIGTERM first, SIGKILL after grace period)
- Expose timeout config to user (wizard asks "scanning small/medium/large target?")

```go
type ToolConfig struct {
    Name    string
    Timeout time.Duration
    GracePeriod time.Duration // time between SIGTERM and SIGKILL
}

// Allow user to scale timeouts
if targetSize == "large" {
    config.Timeout *= 5
}
```

**Detection:**
- Tools consistently killed at timeout boundary
- Incomplete results for large targets
- Pipeline hangs indefinitely (no timeout set)
- Users manually killing processes

**Phase impact:** Initial implementation. Timeout strategy affects architecture.

---

## Moderate Pitfalls

Issues that cause frustration but not rewrites.

### Pitfall 7: DNS Enumeration Duplication
**What goes wrong:** Subfinder, dnsx, dig all enumerate subdomains. Pipeline runs all three, gets duplicate results, wastes time.

**Prevention:**
- Understand tool boundaries (subfinder = discovery, dnsx = validation, dig = specific lookups)
- Don't chain tools that do the same thing
- Deduplicate results before passing to next stage
- Document which tool is authoritative for each data type

---

### Pitfall 8: Missing Dependency Checks
**What goes wrong:** User runs pipeline, gets cryptic errors because nmap/masscan not installed or wrong version.

**Prevention:**
- Preflight dependency check (run `--version` for each tool)
- Clear error messages ("nmap not found. Install: sudo apt install nmap")
- Version requirements documented ("Requires nmap 7.80+")
- Optional: auto-install missing tools (dangerous, needs sudo)

```go
func checkDependencies() error {
    required := map[string]string{
        "nmap": "7.80",
        "subfinder": "2.5.0",
        // ...
    }
    for tool, minVersion := range required {
        if err := verifyTool(tool, minVersion); err != nil {
            return fmt.Errorf("%s: %w. Install: [platform-specific command]", tool, err)
        }
    }
    return nil
}
```

---

### Pitfall 9: Credential Mismanagement
**What goes wrong:** API keys for Shodan, SecurityTrails, etc. hardcoded or in unencrypted config. Accidentally committed to git.

**Prevention:**
- Environment variables for secrets (`SHODAN_API_KEY`)
- Config file with `.gitignore` entry
- Validate keys before use (fail fast if invalid)
- Document which features require which API keys
- Never log full API keys (log `sk_...xxxx` with suffix only)

---

### Pitfall 10: No Graceful Degradation
**What goes wrong:** One tool fails (nuclei timeout), entire pipeline aborts. Lost all previous stage outputs.

**Prevention:**
- Continue on non-critical errors (flag warning, keep going)
- Categorize tools (required vs optional)
- Save intermediate outputs after each stage
- Provide `--continue-on-error` flag for batch scanning

```go
if err := runNuclei(targets); err != nil {
    log.Warnf("Nuclei failed: %v. Continuing with other stages.", err)
    report.Warnings = append(report.Warnings, "Nuclei scan incomplete")
    // Don't return error, continue pipeline
}
```

---

### Pitfall 11: Target Validation Neglect
**What goes wrong:** User inputs `google.com`, pipeline scans Google infrastructure, gets IP banned or legal threat.

**Prevention:**
- Explicit confirmation for known cloud/CDN ranges
- Warn on public IP ranges (AWS, Cloudflare, etc.)
- Scope validation (allow CIDR exclusions)
- Rate limiting more aggressive for public targets
- Legal disclaimer in documentation

```go
func validateTarget(target string) error {
    if isCloudProvider(target) {
        return fmt.Errorf("target appears to be cloud infrastructure. Use --allow-cloud to proceed.")
    }
    if isPublicService(target) {
        log.Warn("Scanning public service. Ensure you have authorization.")
    }
    return nil
}
```

---

### Pitfall 12: Progress Opacity
**What goes wrong:** Pipeline runs for 30 minutes, no output. User doesn't know if it's working or hung.

**Prevention:**
- Stream tool output in real-time (optional verbose mode)
- Progress indicators ("Subfinder: 500 subdomains found...")
- ETA estimates for long-running stages
- Log current stage clearly ("Stage 3/7: Running nmap...")

---

### Pitfall 13: Memory Leaks in Long Pipelines
**What goes wrong:** Scanning hundreds of targets in batch mode, memory climbs until OOM.

**Why it happens:**
- Accumulating all results in memory before writing
- Not closing file handles
- Goroutine leaks (context not cancelled properly)

**Prevention:**
- Stream results to disk (don't hold in RAM)
- Explicit file handle cleanup (defer file.Close())
- Worker pools with bounded concurrency
- Memory profiling during development

---

## Minor Pitfalls

Small issues with easy fixes.

### Pitfall 14: Inconsistent Logging
**What goes wrong:** Some tools log to stdout, some to stderr, some to files. Hard to debug.

**Prevention:**
- Structured logging library (zerolog, logrus)
- Consistent log levels (DEBUG, INFO, WARN, ERROR)
- Capture stdout/stderr from external tools separately
- Log aggregation (all logs to single file for scan)

---

### Pitfall 15: No Version Information in Output
**What goes wrong:** Can't reproduce scan results. Don't know which tool versions produced data.

**Prevention:**
- Record tool versions in manifest.json
- Include pipeline version in reports
- Timestamp all scans
- Git commit hash in version output (for dev builds)

---

### Pitfall 16: Markdown Report Fragility
**What goes wrong:** Special characters in tool output break markdown rendering. Tables misaligned.

**Prevention:**
- Escape markdown special characters in tool output
- Use markdown libraries (goldmark) instead of string templates
- Validate markdown output (render in parser to catch errors)
- Fallback to JSON if markdown generation fails

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation | Priority |
|-------------|---------------|------------|----------|
| Process orchestration | Zombie processes (Pitfall 1) | Process groups, proper cleanup | CRITICAL |
| Output parsing | Brittle parsers (Pitfall 2) | JSON-only, validation | CRITICAL |
| API integration | Rate limiting (Pitfall 3) | Central rate limiter | CRITICAL |
| File management | Output chaos (Pitfall 4) | Structured directories | HIGH |
| Cross-platform | Path assumptions (Pitfall 5) | filepath package, LookPath | HIGH |
| Tool execution | Timeouts (Pitfall 6) | Per-tool config | HIGH |
| Tool selection | Duplication (Pitfall 7) | Clear tool boundaries | MEDIUM |
| Installation | Dependency checks (Pitfall 8) | Preflight validation | HIGH |
| Security | Credential management (Pitfall 9) | Env vars, gitignore | HIGH |
| Error handling | No degradation (Pitfall 10) | Continue on non-critical errors | MEDIUM |
| Legal/scope | Target validation (Pitfall 11) | Cloud detection, warnings | CRITICAL |
| UX | Progress opacity (Pitfall 12) | Streaming output | LOW |
| Batch scanning | Memory leaks (Pitfall 13) | Streaming writes, worker pools | MEDIUM |
| Debugging | Inconsistent logging (Pitfall 14) | Structured logging | LOW |
| Reproducibility | No version info (Pitfall 15) | Version manifest | LOW |
| Reporting | Markdown fragility (Pitfall 16) | Escaping, libraries | LOW |

---

## Testing Blind Spots

### Blind Spot 1: Tool Update Breakage
**Problem:** Tests use mocked tool output. Real tools update, output changes, tests still pass but production breaks.

**Detection:**
- Integration tests with real tools
- Pin tool versions in CI
- Test against multiple tool versions

### Blind Spot 2: Large Target Behavior
**Problem:** Tests use `example.com` with 3 subdomains. Production scans Fortune 500 with 50,000 subdomains.

**Detection:**
- Scale tests (simulate large outputs)
- Memory profiling with realistic data volumes
- Timeout testing with synthetic delays

### Blind Spot 3: Network Failures
**Problem:** Tests assume network always works. Production hits DNS failures, timeouts, connection resets.

**Detection:**
- Chaos engineering (inject failures)
- Test with flaky network simulation
- Offline mode testing

---

## Configuration Footguns

### Footgun 1: Nmap Privilege Assumptions
**Problem:** Some nmap scans require root (SYN scan). Pipeline fails with permission error.

**Solution:**
- Document which scans need sudo
- Fall back to non-privileged scans (TCP connect instead of SYN)
- Clear error messages about privilege requirements

### Footgun 2: Masscan Port Range Explosion
**Problem:** User inputs `-p-` (all 65k ports), masscan hammers network, ISP blocks traffic.

**Solution:**
- Warn on large port ranges
- Rate limit masscan explicitly
- Default to common ports only
- Require confirmation for full port scans

### Footgun 3: Nuclei Template Sprawl
**Problem:** Nuclei has 5,000+ templates. Running all templates takes hours and generates false positives.

**Solution:**
- Template filtering (severity, tags)
- Default to curated subset (critical/high only)
- Allow custom template paths
- Document template selection strategy

---

## Common Anti-Patterns

### Anti-Pattern 1: Shell Script Wrappers
**Bad approach:** Use `sh -c "subfinder | httpx | nuclei"`

**Problems:**
- No error handling (pipeline continues on failures)
- No progress visibility
- Hard to test
- Signal handling broken (Ctrl+C kills shell, not tools)
- Output parsing nightmare

**Better:** Direct process execution with proper lifecycle management.

---

### Anti-Pattern 2: Synchronous Sequential Execution
**Bad approach:** Run subfinder, wait for completion, run httpx, wait, run nuclei...

**Problems:**
- Wastes time (can't parallelize independent stages)
- No streaming (can't start httpx on first subdomain while subfinder still running)

**Better:** Pipeline stages with channels (producer/consumer model).

---

### Anti-Pattern 3: Overwriting Raw Outputs
**Bad approach:** Each run overwrites previous scan outputs.

**Problems:**
- Can't diff scans over time (main feature requirement!)
- Lost data on crashes
- Can't debug parser issues (raw output gone)

**Better:** Timestamped output directories, retention policy.

---

## Scope Creep Traps

### Trap 1: Distributed Scanning
**Temptation:** Add distributed scanning across multiple VPS for speed.

**Reality:** Adds massive complexity (coordination, state sync, failure handling). Not needed for two-person team.

**Recommendation:** Defer until proven bottleneck. Local parallelization sufficient initially.

---

### Trap 2: Real-Time Alerting
**Temptation:** Send Slack/Discord alerts when vulnerabilities found.

**Reality:** Adds notification infrastructure, alert fatigue, configuration complexity.

**Recommendation:** Focus on solid reporting first. Alerts are nice-to-have.

---

### Trap 3: Web Dashboard
**Temptation:** Build web UI for scan management and result viewing.

**Reality:** Doubles project scope. CLI + markdown reports sufficient for power users.

**Recommendation:** CLI-first. Dashboard only if becomes customer tool.

---

## Sources

**Confidence note:** Research conducted without access to web search, Context7, or WebFetch due to tool restrictions. Findings based on:

- Training data on Go process management patterns (MEDIUM confidence)
- Training data on ProjectDiscovery tool ecosystems (MEDIUM confidence)
- Security tool orchestration best practices (MEDIUM confidence)
- Cross-platform Go CLI development patterns (HIGH confidence - well-established)

**Recommended validation:**
- Review ProjectDiscovery GitHub issues for current integration challenges
- Check subfinder/nuclei/httpx documentation for rate limiting guidance
- Consult Go process management libraries (e.g., `github.com/go-cmd/cmd`) for zombie prevention patterns
- Review existing recon automation tools (Axiom, Interlace, Sudomy) for proven approaches

**Known gaps:**
- Current (2026) API rate limits for third-party services
- Recent tool output format changes
- Platform-specific issues on latest Windows/WSL versions
- New tools in ProjectDiscovery ecosystem post-2025

**Phase recommendations:**
- Foundation phase: Pitfalls 1, 4, 5, 6, 8 (process management, file structure, paths, timeouts, dependencies)
- Integration phase: Pitfalls 2, 3, 7, 9 (parsing, rate limits, tool selection, credentials)
- UX phase: Pitfalls 10, 11, 12 (error handling, validation, progress)
- Optimization phase: Pitfalls 13, 14, 15, 16 (memory, logging, versioning, reporting)
