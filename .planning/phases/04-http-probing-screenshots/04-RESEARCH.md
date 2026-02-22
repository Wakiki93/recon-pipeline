# Phase 4: HTTP Probing & Screenshots - Research

**Researched:** 2026-02-22
**Domain:** HTTP probing (httpx), screenshot capture (gowitness), vhost detection, CDN tagging
**Confidence:** HIGH

## Summary

Phase 4 extends the existing reconpipe pipeline to detect live HTTP services on all discovered open ports and capture screenshots for visual triage. The two external tools are httpx (ProjectDiscovery) and gowitness v3 (sensepost). Both are Go binaries already referenced in `internal/tools/checker.go` and `internal/config/config.go`, meaning their integration slots are pre-established — no config changes are required beyond adding `HttpxThreads` validation that already exists in `config.go`.

The core challenge in this phase is the two-pass probe strategy: httpx must run against BOTH raw IP:port combinations (to discover services regardless of hostname) AND against subdomain:port combinations (to detect vhost-bound services that only respond to specific hostnames). This dual-probe approach produces a combined deduplicated result set. CDN tagging (CDN-03) is a post-probe step: after httpx results are collected, each probe result is annotated with CDN info from existing `models.Host.IsCDN` and `models.Host.CDNProvider` fields that Phase 3 already populated.

The pipeline pattern is identical to Phase 3: tool wrappers in `internal/tools/`, pipeline logic in `internal/httpprobe/`, a report generator in `internal/report/`, and a CLI command in `cmd/reconpipe/`. The `models.HTTPProbe` struct is already defined in `internal/models/host.go` with all needed fields. No new models are required — only the tool wrappers, pipeline, report, and CLI command are new files.

**Primary recommendation:** Follow the exact Phase 3 pattern. RunHttpx uses stdin piping (same as cdncheck.go, not RunTool), parses JSONL. RunGowitness uses RunTool with temp URL file. Pipeline in `internal/httpprobe/pipeline.go`. Report in `internal/report/http.go`. CLI in `cmd/reconpipe/probe.go`.

## Standard Stack

### Core
| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| httpx | latest | HTTP probing with status, title, tech detection, CDN detection | ProjectDiscovery standard; already in checker.go and config |
| gowitness | v3.1.1 | Headless Chrome screenshot capture | Only maintained Go screenshotter; v3 is current |

### Supporting
| Tool/Library | Version | Purpose | When to Use |
|---|---|---|---|
| encoding/json (stdlib) | Go stdlib | Parse httpx JSONL output | Every httpx result line |
| bufio.Scanner (stdlib) | Go stdlib | Line-by-line JSONL reading | Same as cdncheck parsing pattern |
| os.CreateTemp (stdlib) | Go stdlib | Temp file for gowitness URL list | Same as masscan temp file pattern |
| strings.Builder (stdlib) | Go stdlib | Markdown report generation | Same as existing report files |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| httpx | aquatone | aquatone is largely abandoned; httpx is actively maintained |
| gowitness v3 | gowitness v2 | v2 has different command structure (`gowitness file` not `gowitness scan file`); v3 is current |
| gowitness | aquatone screenshot | aquatone unmaintained; avoid |

**Installation:**
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/sensepost/gowitness@latest
```

## Architecture Patterns

### Recommended Project Structure

New files for Phase 4 (following Phase 3 pattern exactly):
```
internal/
├── tools/
│   ├── httpx.go        # httpx wrapper (new)
│   └── gowitness.go    # gowitness wrapper (new)
├── httpprobe/
│   └── pipeline.go     # HTTP probe pipeline (new)
└── report/
    └── http.go         # http-probes.md report generator (new)
cmd/reconpipe/
└── probe.go            # 'probe' CLI command (new)
```

Modified files:
- `configs/reconpipe.yaml` — add gowitness screenshot_path default (no Go code changes needed; config fields already exist)
- `internal/tools/checker.go` — already lists httpx and gowitness (no changes needed)

### Pattern 1: httpx Tool Wrapper (stdin pipe, JSONL output)

**What:** RunHttpx pipes targets line-by-line to httpx stdin, parses JSONL stdout.
**When to use:** Identical to cdncheck.go pattern — httpx requires stdin input like cdncheck, NOT RunTool.
**Why NOT RunTool:** RunTool buffers all stdout after the command finishes. httpx and cdncheck both benefit from stdin piping and don't write to a temp file. The cdncheck.go pattern (manual exec.CommandContext with stdin/stdout pipes) is the correct template.

```go
// Source: pattern from internal/tools/cdncheck.go
// RunHttpx executes httpx against a list of targets and returns parsed probe results.
// Targets can be bare hostnames, IPs, IP:port, subdomain:port, or full URLs.
// It pipes targets via stdin and parses JSONL output.
func RunHttpx(ctx context.Context, targets []string, threads int, binaryPath string) ([]HttpxResult, error) {
    if len(targets) == 0 {
        return []HttpxResult{}, nil
    }

    binary := "httpx"
    if binaryPath != "" {
        binary = binaryPath
    }

    args := []string{
        "-json",    // JSONL output
        "-silent",  // suppress banner
        "-sc",      // status code
        "-title",   // page title
        "-server",  // web server header
        "-td",      // technology detection
        "-cdn",     // CDN detection
        "-ip",      // include IP in output
        "-t", strconv.Itoa(threads), // thread count
    }

    cmd := exec.CommandContext(ctx, binary, args...)
    cmd.WaitDelay = 5 * time.Second

    stdinPipe, _ := cmd.StdinPipe()
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()

    cmd.Start()

    // Write targets to stdin concurrently (same as cdncheck.go)
    go func() {
        defer stdinPipe.Close()
        for _, target := range targets {
            fmt.Fprintln(stdinPipe, target)
        }
    }()

    // Read stdout/stderr concurrently (same as cdncheck.go)
    // ... parse JSONL output into []HttpxResult
}
```

### Pattern 2: httpx JSON Output Structure

**What:** httpx with `-json` flag outputs one JSON object per line (JSONL).
**Verified field names** (from pkg.go.dev/github.com/projectdiscovery/httpx/runner, HIGH confidence):

```go
// Source: https://pkg.go.dev/github.com/projectdiscovery/httpx/runner
type HttpxResult struct {
    URL           string   `json:"url"`
    Input         string   `json:"input"`      // original input target
    StatusCode    int      `json:"status_code"`
    Title         string   `json:"title"`
    ContentLength int64    `json:"content_length"`
    WebServer     string   `json:"webserver"`
    Technologies  []string `json:"tech"`        // NOTE: field is "tech" not "technologies"
    HostIP        string   `json:"host"`        // resolved IP — NOTE: field is "host" not "ip"
    Port          string   `json:"port"`        // string, not int
    CDN           bool     `json:"cdn"`
    CDNName       string   `json:"cdn_name"`
}
```

**Critical:** The JSON tag `"tech"` (not `"technologies"`) and `"host"` (not `"ip"`) are the actual field names used by httpx. Verify against live output during implementation.

### Pattern 3: Two-Pass Probe Strategy for Vhost Detection

**What:** Run httpx twice — once with raw IP:port targets (HTTP-01/HTTP-03), once with subdomain:port targets (HTTP-02 vhost detection). Deduplicate results by URL.
**When to use:** Always — this is required to satisfy both HTTP-02 and HTTP-03.

```go
// Pass 1: IP:port targets (detects services bound to any IP)
// Input format: "http://1.2.3.4:8080", "https://1.2.3.4:443"
ipTargets := buildIPTargets(hosts) // e.g., "1.2.3.4:80", "1.2.3.4:8080"
ipResults, _ := tools.RunHttpx(ctx, ipTargets, cfg.HttpxThreads, cfg.HttpxPath)

// Pass 2: subdomain:port targets (detects vhost-bound services)
// Input format: "http://sub.example.com:8080", "https://sub.example.com"
subTargets := buildSubdomainTargets(hosts) // e.g., "sub.example.com:80"
subResults, _ := tools.RunHttpx(ctx, subTargets, cfg.HttpxThreads, cfg.HttpxPath)

// Merge and deduplicate by URL
allResults := deduplicate(append(ipResults, subResults...))
```

**Input format for non-standard ports:** httpx accepts `host:port` and will probe both http and https automatically. Use bare `host:port` format (no scheme) to let httpx try both, or explicit `http://host:port` / `https://host:port`.

**Vhost detection rationale:** When probing IP `1.2.3.4:8080`, a server that only responds to `Host: app.example.com` will return 400/403 on the raw IP probe. The subdomain probe (`app.example.com:8080`) sends the correct Host header and gets a real response. The difference reveals vhost-bound services.

### Pattern 4: gowitness Tool Wrapper (temp URL file, RunTool)

**What:** RunGowitness writes live HTTP URLs to a temp file, runs `gowitness scan file -f <file>`, screenshots go to a specified directory.
**When to use:** After httpx returns live HTTP endpoints. Only probe 200-range status codes for screenshots to avoid noise.

```go
// Source: gowitness v3 official docs
// gowitness scan file -f urls.txt -s ./screenshots -t 6 -T 60
func RunGowitness(ctx context.Context, urls []string, screenshotDir string, threads int, binaryPath string) error {
    if len(urls) == 0 {
        return nil
    }

    binary := "gowitness"
    if binaryPath != "" {
        binary = binaryPath
    }

    // Write URLs to temp file (same as masscan pattern)
    inputFile, _ := os.CreateTemp("", "gowitness-urls-*.txt")
    defer os.Remove(inputFile.Name())
    for _, url := range urls {
        fmt.Fprintln(inputFile, url)
    }
    inputFile.Close()

    args := []string{
        "scan", "file",
        "-f", inputFile.Name(),
        "-s", screenshotDir,          // screenshot output directory
        "-t", strconv.Itoa(threads),  // thread count (default 6)
        "-T", "60",                   // timeout in seconds
        "--screenshot-format", "png", // png for lossless quality
    }

    _, err := RunTool(ctx, binary, args...)
    return err
}
```

**gowitness v3 key flags** (verified from source code and release notes, HIGH confidence):
- `scan file` — subcommand for file-based scanning (BREAKING CHANGE from v2 `file` command)
- `-f, --file` — input file path (use `-` for stdin)
- `-s, --screenshot-path` — screenshot output directory (default `./screenshots`)
- `-t, --threads` — concurrent goroutines (default 6)
- `-T, --timeout` — page timeout in seconds (default 60)
- `--screenshot-format` — `jpeg` (default) or `png`

### Pattern 5: CDN Post-Probe Tagging

**What:** After httpx probing, annotate `models.HTTPProbe` results with CDN info from Phase 3 `models.Host` data.
**When to use:** CDN-03 requirement — tag CDN presence in probe results without re-running cdncheck.

```go
// Build IP -> CDN info map from Phase 3 hosts
cdnMap := make(map[string]struct{ IsCDN bool; CDNProvider string })
for _, host := range hosts {
    cdnMap[host.IP] = struct{ IsCDN bool; CDNProvider string }{
        IsCDN: host.IsCDN, CDNProvider: host.CDNProvider,
    }
}

// Annotate probe results
for i, probe := range probes {
    if cdnInfo, ok := cdnMap[probe.IP]; ok {
        probes[i].IsCDN = cdnInfo.IsCDN
        probes[i].CDNProvider = cdnInfo.CDNProvider
    }
}
```

Note: `models.HTTPProbe` does NOT currently have `IsCDN`/`CDNProvider` fields — they must be added to the struct. The CDN info flows from `models.Host` (set in Phase 3) to `models.HTTPProbe` (new in Phase 4) via the annotation step.

### Pattern 6: Pipeline Config and Result Structs

```go
// internal/httpprobe/pipeline.go

type HTTPProbeConfig struct {
    HttpxPath       string
    GowitnessPath   string
    HttpxThreads    int
    ScreenshotDir   string
    SkipScreenshots bool
}

type HTTPProbeResult struct {
    Target        string             `json:"target"`
    Probes        []models.HTTPProbe `json:"probes"`
    LiveCount     int                `json:"live_count"`
    ScreenshotDir string             `json:"screenshot_dir"`
}
```

### Pattern 7: Input Data Flow from Phase 3

Phase 4 reads from Phase 3 output. Input is `ports.json` containing `portscan.PortScanResult`.

```go
// In probe CLI command (cmd/reconpipe/probe.go):
// Read ports.json from prior portscan
portsPath := filepath.Join(scanDir, "raw", "ports.json")
data, _ := os.ReadFile(portsPath)
var portResult portscan.PortScanResult
json.Unmarshal(data, &portResult)

// Pass hosts to probe pipeline
result, err := httpprobe.RunHTTPProbe(ctx, portResult.Hosts, cfg)
```

### Anti-Patterns to Avoid

- **Using RunTool for httpx:** httpx requires stdin piping; use manual exec.CommandContext (same as cdncheck.go). RunTool does not support stdin piping.
- **Probing only ports 80/443:** HTTP-03 requires probing ALL discovered open ports. Build targets from `host.Ports` not from a hardcoded list.
- **Only probing raw IPs:** HTTP-02 requires also probing via subdomain hostname (vhost detection). Both passes required.
- **Using gowitness v2 command structure:** v2 used `gowitness file -f urls.txt`. v3 uses `gowitness scan file -f urls.txt`. Using v2 syntax against a v3 binary will fail.
- **Screenshotting all HTTP results:** Only screenshot 200-range status codes to avoid noise and timeout overhead on error pages.
- **Creating screenshot directory inside gowitness call:** Create it before RunGowitness using `storage.EnsureDir(screenshotDir)`.
- **Hardcoding screenshot directory:** Read `ScreenshotDir` from config or derive from scan directory: `{scanDir}/screenshots/`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP probing | Custom HTTP client with net/http | httpx | httpx handles TLS, redirects, tech fingerprinting, CDN detection — massive complexity |
| Technology detection | Wappalyzer port in Go | httpx -td flag | httpx bundles wappalyzer signatures; maintaining them is a full-time job |
| Screenshot capture | chromedp directly | gowitness | gowitness handles Chrome lifecycle, headless mode, screenshot cropping, timeouts |
| CDN detection | Re-run cdncheck on probe results | Annotate from Phase 3 data | Phase 3 already ran cdncheck; reading from Host.CDNProvider is free and consistent |
| JSONL parsing | Custom parser | bufio.Scanner + json.Unmarshal | Standard pattern already used in cdncheck.go |

**Key insight:** Both httpx and gowitness handle production-grade complexities (TLS, redirects, headless browser lifecycle) that would take weeks to replicate. The tool wrappers are thin shells around proven binaries.

## Common Pitfalls

### Pitfall 1: httpx JSON Field Name Mismatch

**What goes wrong:** Struct tags like `json:"technologies"` or `json:"ip"` produce empty slices/strings because httpx uses `json:"tech"` and `json:"host"`.
**Why it happens:** httpx's internal field names differ from intuitive names. Documentation is incomplete on exact JSON field names.
**How to avoid:** Verify field names with `echo "example.com" | httpx -json 2>/dev/null | head -1 | python3 -m json.tool` during development. The key fields confirmed are:
- Technologies: `"tech"` (not `"technologies"`)
- IP: `"host"` (not `"ip"` or `"host_ip"`) — MEDIUM confidence, verify against live output
- Port: `"port"` (string, not int)
**Warning signs:** HTTPProbe.Technologies is always empty even when httpx outputs show technologies.

### Pitfall 2: gowitness v2 vs v3 Command Structure Breaking Change

**What goes wrong:** `gowitness file -f urls.txt` fails with "unknown command" on v3 installations.
**Why it happens:** gowitness v3 moved all scan subcommands under `scan`: `gowitness scan file -f urls.txt`.
**How to avoid:** Always use v3 syntax: `gowitness scan file -f <file>`. Add version check to tool checker or document minimum version requirement.
**Warning signs:** gowitness exits non-zero with "unknown command 'file'" error message.

### Pitfall 3: Target Format for Non-Standard Ports

**What goes wrong:** httpx only probes port 80 and 443 even though masscan found 8080, 8443, 9000.
**Why it happens:** If targets are passed as bare hostnames (`example.com`, `1.2.3.4`), httpx defaults to 80/443. Port must be included in the target string.
**How to avoid:** Build targets as `host:port` strings, e.g., `sub.example.com:8080`, `1.2.3.4:8080`. httpx will probe both http and https on that port. Do NOT use `-ports` flag separately — it applies globally to all targets, not per-target.
**Warning signs:** HTTPProbeResult.Probes only contains port 80 and 443 entries even when open ports include 8080.

### Pitfall 4: Screenshot Directory Must Pre-Exist

**What goes wrong:** gowitness fails with "permission denied" or "no such directory" when screenshot directory doesn't exist.
**Why it happens:** gowitness does not create the screenshot directory automatically (behavior confirmed from user reports).
**How to avoid:** Call `storage.EnsureDir(screenshotDir)` before `RunGowitness()`. Use `{scanDir}/screenshots/` as the directory.
**Warning signs:** gowitness exits with directory creation error before taking any screenshots.

### Pitfall 5: Empty HTTPProbe Model Missing CDN Fields

**What goes wrong:** CDN-03 requirement cannot be satisfied because `models.HTTPProbe` struct has no `IsCDN`/`CDNProvider` fields.
**Why it happens:** The existing `models.HTTPProbe` struct (defined in `internal/models/host.go`) does not include CDN annotation fields.
**How to avoid:** Add `IsCDN bool` and `CDNProvider string` fields to `models.HTTPProbe` before implementing the pipeline. This is a model change that must happen in the first task.
**Warning signs:** Compiler error when trying to assign `probe.IsCDN = true`.

### Pitfall 6: Duplicate Probe Results from Two-Pass Strategy

**What goes wrong:** The same URL appears twice in probe results (once from IP pass, once from subdomain pass), causing duplicate entries in the report.
**Why it happens:** A vhost-bound service responds to both `http://1.2.3.4:80` and `http://app.example.com:80` — these are different URLs but the same service.
**How to avoid:** Deduplicate by URL in the merge step: `seen := make(map[string]bool)`, skip if `seen[result.URL]`. Report by URL, not by input target.
**Warning signs:** http-probes.md shows the same page title appearing for two different URL entries.

### Pitfall 7: Gowitness Chrome/Chromium Dependency

**What goes wrong:** gowitness fails with "chrome not found" or "chromium not found" error.
**Why it happens:** gowitness requires a Chrome or Chromium binary to render pages. It is NOT bundled with gowitness.
**How to avoid:** Add Chrome/Chromium as a documented system dependency. Check with `gowitness scan single https://example.com` before integrating. In the CLI, print a clear error message if gowitness fails (treat as optional like cdncheck).
**Warning signs:** gowitness exits immediately with a Chrome-related error on fresh installs.

## Code Examples

Verified patterns from official sources and codebase:

### Building Target Strings for httpx (Both Passes)

```go
// Source: derived from codebase patterns and httpx docs
// Pass 1: IP:port targets
func buildIPTargets(hosts []models.Host) []string {
    var targets []string
    seen := make(map[string]bool)
    for _, host := range hosts {
        if host.IsCDN {
            continue // skip CDN IPs - they won't serve real content
        }
        for _, port := range host.Ports {
            target := fmt.Sprintf("%s:%d", host.IP, port.Number)
            if !seen[target] {
                targets = append(targets, target)
                seen[target] = true
            }
        }
    }
    return targets
}

// Pass 2: subdomain:port targets (vhost detection)
func buildSubdomainTargets(hosts []models.Host) []string {
    var targets []string
    seen := make(map[string]bool)
    for _, host := range hosts {
        for _, subdomain := range host.Subdomains {
            for _, port := range host.Ports {
                target := fmt.Sprintf("%s:%d", subdomain, port.Number)
                if !seen[target] {
                    targets = append(targets, target)
                    seen[target] = true
                }
            }
        }
    }
    return targets
}
```

### Parsing httpx JSONL Output

```go
// Source: modeled on internal/tools/cdncheck.go JSONL parsing pattern
var results []HttpxResult
scanner := bufio.NewScanner(bytes.NewReader(stdoutBuf.Bytes()))
for scanner.Scan() {
    line := scanner.Bytes()
    if len(line) == 0 {
        continue
    }
    var result HttpxResult
    if err := json.Unmarshal(line, &result); err != nil {
        fmt.Printf("Warning: failed to parse httpx JSON line: %v\n", err)
        continue
    }
    results = append(results, result)
}
```

### Screenshot Path Convention

```go
// Source: filesystem.go ScanDirPath pattern
screenshotDir := filepath.Join(scanDir, "screenshots")
if err := storage.EnsureDir(screenshotDir); err != nil {
    return nil, fmt.Errorf("creating screenshot directory: %w", err)
}

// Screenshot path for an individual probe (stored in HTTPProbe.ScreenshotPath)
// gowitness names files by URL hash: {screenshotDir}/{hash}.png
// Store relative path in HTTPProbe for report portability
probe.ScreenshotPath = screenshotDir // dir reference, not individual file
```

### HTTP Probe Report Structure

```go
// Source: modeled on internal/report/ports.go pattern
// Report: {scanDir}/reports/http-probes.md
func WriteHTTPProbeReport(result *httpprobe.HTTPProbeResult, outputPath string) error {
    var b strings.Builder

    b.WriteString("# HTTP Probe Report\n\n")
    b.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
    b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
    b.WriteString(fmt.Sprintf("**Live services:** %d\n\n", result.LiveCount))

    b.WriteString("## Live HTTP Services\n\n")
    if len(result.Probes) > 0 {
        b.WriteString("| URL | Status | Title | Server | Technologies | CDN | Screenshot |\n")
        b.WriteString("|-----|--------|-------|--------|-------------|-----|------------|\n")
        for _, probe := range result.Probes {
            tech := strings.Join(probe.Technologies, ", ")
            cdnTag := ""
            if probe.IsCDN {
                cdnTag = probe.CDNProvider
            }
            screenshotRef := "-"
            if probe.ScreenshotPath != "" {
                screenshotRef = "yes"
            }
            b.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %s |\n",
                probe.URL, probe.StatusCode, probe.Title, probe.WebServer,
                tech, cdnTag, screenshotRef))
        }
    } else {
        b.WriteString("No live HTTP services found.\n")
    }
    // ...
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `gowitness file -f urls.txt` | `gowitness scan file -f urls.txt` | gowitness v3.0.0 (late 2024) | Using v2 syntax on v3 binary causes "unknown command" failure |
| gowitness JPEG default | gowitness JPEG still default | v3.0.0 | Use `--screenshot-format png` for lossless if needed |
| Probe only 80/443 | Probe all discovered ports | Best practice 2025 | Non-standard HTTP services (8080, 8443, 3000, 5000) common in bug bounty |
| httpx v1 separate binary | httpx unified binary | 2022+ | Same binary, actively maintained |

**Deprecated/outdated:**
- aquatone: unmaintained, use gowitness instead
- `gowitness file` (v2 command): replaced by `gowitness scan file` in v3

## Open Questions

1. **httpx JSON field name for IP**
   - What we know: pkg.go.dev shows `host_ip` but some sources indicate `host`. Field `"ip"` is also common in documentation.
   - What's unclear: Exact JSON field name for the resolved IP address in httpx output.
   - Recommendation: During implementation, run `echo "example.com" | httpx -json 2>/dev/null | python3 -m json.tool` to inspect actual output. Use the correct tag in `HttpxResult` struct. Mark as LOW confidence until verified.

2. **gowitness screenshot file naming convention**
   - What we know: gowitness saves screenshots to the `--screenshot-path` directory. v3 uses a database or JSONL for metadata.
   - What's unclear: Exact filename format gowitness uses for screenshots (hash-based? domain-based?).
   - Recommendation: Store the screenshot directory path in `HTTPProbe.ScreenshotPath` rather than individual file paths. The report can reference the directory. Individual file lookup can be added in Phase 6+ if needed.

3. **gowitness JSONL output format**
   - What we know: gowitness supports `--write-jsonl` / `--write-jsonl-file` for structured output.
   - What's unclear: Exact JSONL fields and whether screenshot file paths are included.
   - Recommendation: For Phase 4, skip `--write-jsonl` — gowitness is only needed for screenshot side-effects, not data extraction. httpx handles all data. Gowitness is fire-and-forget.

4. **httpx behavior on non-HTTP ports**
   - What we know: httpx probes both http and https by default when given `host:port`.
   - What's unclear: Does httpx skip ports that return SSH or SMTP banners gracefully, or does it emit error lines?
   - Recommendation: The JSONL parser already skips malformed lines (see cdncheck.go pattern). Non-HTTP ports will either time out or be skipped by httpx's internal probing logic. No special handling needed.

## Sources

### Primary (HIGH confidence)
- `internal/tools/cdncheck.go` — stdin piping pattern to replicate for httpx
- `internal/tools/masscan.go` — temp file pattern to replicate for gowitness
- `internal/portscan/pipeline.go` — two-pass pipeline pattern
- `internal/models/host.go` — HTTPProbe struct (fields verified in codebase)
- `internal/config/config.go` — HttpxThreads and Httpx/Gowitness ToolConfig already defined
- https://pkg.go.dev/github.com/projectdiscovery/httpx/runner — JSON field names
- https://github.com/sensepost/gowitness/releases/tag/3.0.0 — v3 breaking changes, v3 command structure
- https://github.com/sensepost/gowitness/blob/master/cmd/scan_file.go — exact flag names (-f, -s, -t, -T)

### Secondary (MEDIUM confidence)
- https://docs.projectdiscovery.io/tools/httpx/running — httpx flags verified against official ProjectDiscovery docs
- https://kb.offsec.nl/tools/framework/gowitness/scan/ — gowitness v3 scan flags (-s, -t, -T, --write-jsonl)
- WebSearch "gowitness v3 scan file 2025" — confirmed v2→v3 command change, confirmed -f flag

### Tertiary (LOW confidence)
- httpx JSON field names `"tech"` and `"host"` — from pkg.go.dev but not verified against live output. Treat as hypothesis until confirmed during implementation.
- gowitness screenshot filename format — not verified, treated as unknown (see Open Questions)

## File Plan

New files to create (7 total):
1. `internal/tools/httpx.go` — httpx wrapper with stdin pipe (RunHttpx, HttpxResult)
2. `internal/tools/gowitness.go` — gowitness wrapper with temp file (RunGowitness)
3. `internal/httpprobe/pipeline.go` — HTTP probe pipeline (RunHTTPProbe, HTTPProbeConfig, HTTPProbeResult)
4. `internal/report/http.go` — http-probes.md report generator (WriteHTTPProbeReport)
5. `cmd/reconpipe/probe.go` — 'probe' CLI command

Modified files (2 total):
6. `internal/models/host.go` — add `IsCDN bool` and `CDNProvider string` to HTTPProbe struct
7. `configs/reconpipe.yaml` — add `screenshot_path` under gowitness tool config (optional, can use scan dir default)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — httpx and gowitness are pre-established in checker.go and config.go; both are the current standard
- Architecture: HIGH — Phase 3 pipeline pattern is fully read and understood; new phase follows it exactly
- Pitfalls: HIGH — most pitfalls derived from reading actual codebase code, v3 breaking changes from official release notes
- httpx JSON field names: LOW — not verified against live output; must confirm during implementation

**Research date:** 2026-02-22
**Valid until:** 2026-03-22 (30 days; tools are stable but httpx field names need live verification)
