# Architecture Patterns

**Domain:** Security Recon Pipeline CLI
**Researched:** 2026-02-14
**Confidence:** MEDIUM (based on training data and Go CLI best practices)

## Recommended Architecture

### High-Level Structure

```
reconpipe (CLI entry point)
├── cmd/                    # Cobra commands (run, diff, wizard, etc.)
│   ├── root.go            # Root command + global flags
│   ├── run.go             # Execute pipeline stages
│   ├── diff.go            # Compare historical scans
│   └── wizard.go          # Interactive mode
├── internal/
│   ├── pipeline/          # Pipeline orchestration
│   │   ├── executor.go    # Run stages sequentially/parallel
│   │   ├── stage.go       # Stage interface + implementations
│   │   └── context.go     # Pipeline context (config, state)
│   ├── tools/             # External tool wrappers
│   │   ├── subfinder.go   # Subfinder execution + parsing
│   │   ├── httpx.go       # Httpx execution + parsing
│   │   ├── nuclei.go      # Nuclei execution + parsing
│   │   └── ...            # One file per tool
│   ├── storage/           # Persistence layer
│   │   ├── bbolt.go       # Scan history storage
│   │   └── models.go      # Data structures
│   ├── report/            # Output generation
│   │   ├── markdown.go    # Markdown report generation
│   │   └── templates/     # text/template files
│   ├── diff/              # Scan comparison logic
│   │   ├── differ.go      # Diff algorithm
│   │   └── dns.go         # Dangling DNS detection
│   └── config/            # Configuration management
│       └── config.go      # Viper-based config
└── pkg/                   # Public APIs (if needed for extensions)
```

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| **cmd/** | CLI interface, flag parsing, command routing | internal/pipeline, internal/config |
| **internal/pipeline** | Orchestrate stages, handle dependencies, manage state | internal/tools, internal/storage, internal/report |
| **internal/tools** | Execute external tools, parse outputs, normalize data | external tools (subfinder, nmap, etc.) |
| **internal/storage** | Persist scan results, retrieve history for diffs | bbolt database |
| **internal/report** | Generate markdown reports from scan data | internal/pipeline (data source) |
| **internal/diff** | Compare scans, detect changes, flag dangling DNS | internal/storage (historical data) |
| **internal/config** | Load config files, merge with flags and env vars | viper library |

### Data Flow

```
User Input (CLI/Wizard)
    ↓
cmd/ (parse, validate)
    ↓
internal/config (load settings)
    ↓
internal/pipeline/executor
    ↓
    ├→ Stage 1: Subdomain Enumeration
    │    ↓
    │  internal/tools/subfinder.go
    │    ↓
    │  Parse JSON → []Subdomain
    │    ↓
    │  internal/storage (save intermediate)
    │    ↓
    │  internal/report (markdown: subdomains.md)
    │
    ├→ Stage 2: Live Host Detection
    │    ↓
    │  internal/tools/httpx.go (read Stage 1 output)
    │    ↓
    │  Parse JSON → []LiveHost
    │    ↓
    │  internal/storage (save intermediate)
    │    ↓
    │  internal/report (markdown: live-hosts.md)
    │
    └→ Stage N: Vulnerability Scanning
         ↓
       internal/tools/nuclei.go (read Stage 2+ output)
         ↓
       Parse JSON → []Vulnerability
         ↓
       internal/storage (save final results)
         ↓
       internal/report (markdown: vulnerabilities.md)

Final Output:
├── reports/2026-02-14_15-30/
│   ├── subdomains.md
│   ├── live-hosts.md
│   ├── ports.md
│   └── vulnerabilities.md
└── .reconpipe.db (bbolt storage)
```

### Concurrency Model

**Sequential by default, parallel where safe:**

```go
// Stage dependencies
Stage 1: Subdomain Enumeration (parallel: subfinder + amass)
    ↓ (merge + dedupe)
Stage 2: DNS Resolution (parallel per subdomain)
    ↓ (collect results)
Stage 3a: HTTP Probing (parallel: httpx)
    ↓
Stage 3b: Screenshots (parallel: gowitness)
    ↓
Stage 4: Port Scanning (parallel per host, rate-limited)
    ↓
Stage 5: Vulnerability Scanning (parallel per host, rate-limited)
```

**Synchronization:** errgroup for parallel execution within stages, wait before next stage.

## Patterns to Follow

### Pattern 1: Stage Interface

**What:** Standardize how stages execute and report

**When:** Every pipeline stage (subfinder, httpx, nuclei, etc.)

**Example:**
```go
type Stage interface {
    Name() string
    Run(ctx context.Context, input StageInput) (*StageOutput, error)
    Validate() error  // Check tool availability before run
}

type StageInput struct {
    Config    *config.Config
    Previous  *StageOutput  // Output from prior stage
    WorkDir   string
}

type StageOutput struct {
    Data      interface{}   // Parsed results
    RawFiles  []string      // Tool output files
    Metadata  StageMetadata // Duration, errors, etc.
}

// Example implementation
type SubfinderStage struct {
    toolPath string
}

func (s *SubfinderStage) Run(ctx context.Context, input StageInput) (*StageOutput, error) {
    // 1. Build command
    cmd := exec.CommandContext(ctx, s.toolPath, "-d", input.Config.Domain, "-json")

    // 2. Execute
    output, err := cmd.Output()

    // 3. Parse
    subdomains := parseSubfinderJSON(output)

    // 4. Return normalized output
    return &StageOutput{Data: subdomains}, nil
}
```

**Why:** Uniform interface enables pipeline to orchestrate any stage generically.

### Pattern 2: Tool Wrapper Pattern

**What:** Isolate external tool execution, parsing, and error handling

**When:** Every external tool (subfinder, nmap, nuclei)

**Example:**
```go
type SubfinderWrapper struct {
    path string
}

func (w *SubfinderWrapper) Execute(domain string, opts Options) ([]Subdomain, error) {
    // Validate tool exists
    if !w.IsInstalled() {
        return nil, ErrToolNotFound
    }

    // Build command
    args := []string{"-d", domain, "-json"}
    if opts.Recursive {
        args = append(args, "-recursive")
    }

    cmd := exec.Command(w.path, args...)

    // Capture output
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    // Execute with timeout
    ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
    defer cancel()

    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("subfinder failed: %w, stderr: %s", err, stderr.String())
    }

    // Parse JSON output
    return w.parseJSON(stdout.Bytes())
}

func (w *SubfinderWrapper) parseJSON(data []byte) ([]Subdomain, error) {
    // Handle line-delimited JSON
    scanner := bufio.NewScanner(bytes.NewReader(data))
    var subdomains []Subdomain

    for scanner.Scan() {
        var sub Subdomain
        if err := json.Unmarshal(scanner.Bytes(), &sub); err != nil {
            return nil, err
        }
        subdomains = append(subdomains, sub)
    }

    return subdomains, nil
}
```

**Why:** Separates tool-specific logic from pipeline logic. Easy to test, mock, and swap tools.

### Pattern 3: Storage Layer Abstraction

**What:** Decouple storage implementation from business logic

**When:** Saving scan results, querying history for diffs

**Example:**
```go
type Storage interface {
    SaveScan(scan *Scan) error
    GetScan(id string) (*Scan, error)
    ListScans(domain string) ([]*ScanMetadata, error)
    GetLatestScan(domain string) (*Scan, error)
}

type BboltStorage struct {
    db *bbolt.DB
}

func (s *BboltStorage) SaveScan(scan *Scan) error {
    return s.db.Update(func(tx *bbolt.Tx) error {
        bucket := tx.Bucket([]byte("scans"))

        // Serialize scan to gob
        var buf bytes.Buffer
        if err := gob.NewEncoder(&buf).Encode(scan); err != nil {
            return err
        }

        // Key: domain:timestamp
        key := fmt.Sprintf("%s:%d", scan.Domain, scan.Timestamp.Unix())
        return bucket.Put([]byte(key), buf.Bytes())
    })
}
```

**Why:** Can swap bbolt for SQLite or filesystem later without changing pipeline code.

### Pattern 4: Context-Based Cancellation

**What:** Propagate cancellation signals through pipeline

**When:** Long-running scans that users might Ctrl+C

**Example:**
```go
func (e *Executor) Run(ctx context.Context, stages []Stage) error {
    for i, stage := range stages {
        select {
        case <-ctx.Done():
            return fmt.Errorf("pipeline cancelled at stage %d: %w", i, ctx.Err())
        default:
        }

        // Run stage with context
        output, err := stage.Run(ctx, input)
        if err != nil {
            return fmt.Errorf("stage %s failed: %w", stage.Name(), err)
        }

        input = output // Chain to next stage
    }
    return nil
}

// CLI layer
cmd.Run = func(cmd *cobra.Command, args []string) error {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Handle Ctrl+C
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-sigChan
        fmt.Println("\nCancelling scan...")
        cancel()
    }()

    return executor.Run(ctx, stages)
}
```

**Why:** Clean shutdown, saves partial results, prevents orphaned processes.

### Pattern 5: Idempotent Stages (Resume Support)

**What:** Track stage completion, skip already-completed stages

**When:** Implementing resume capability

**Example:**
```go
type StateTracker struct {
    storage Storage
    scanID  string
}

func (t *StateTracker) IsStageComplete(stageName string) (bool, error) {
    state, err := t.storage.GetScanState(t.scanID)
    if err != nil {
        return false, err
    }

    return state.CompletedStages[stageName], nil
}

func (t *StateTracker) MarkStageComplete(stageName string) error {
    return t.storage.UpdateScanState(t.scanID, func(state *ScanState) {
        state.CompletedStages[stageName] = true
        state.LastUpdated = time.Now()
    })
}

// In pipeline executor
func (e *Executor) RunWithResume(ctx context.Context, stages []Stage, tracker *StateTracker) error {
    for _, stage := range stages {
        complete, err := tracker.IsStageComplete(stage.Name())
        if err != nil {
            return err
        }

        if complete {
            fmt.Printf("Skipping %s (already complete)\n", stage.Name())
            continue
        }

        output, err := stage.Run(ctx, input)
        if err != nil {
            return err
        }

        // Mark complete AFTER successful execution
        if err := tracker.MarkStageComplete(stage.Name()); err != nil {
            return err
        }
    }
    return nil
}
```

**Why:** Long scans can crash/cancel midway. Resume from last checkpoint instead of restarting.

## Anti-Patterns to Avoid

### Anti-Pattern 1: Hardcoded Tool Paths

**What:** `exec.Command("/usr/bin/subfinder", ...)` instead of resolving from PATH

**Why bad:** Breaks across systems (macOS vs Linux), fails if user installed tools differently

**Instead:**
```go
func findTool(name string) (string, error) {
    // Check PATH first
    path, err := exec.LookPath(name)
    if err == nil {
        return path, nil
    }

    // Check common locations
    commonPaths := []string{
        filepath.Join(os.Getenv("HOME"), "go", "bin", name),
        filepath.Join("/usr/local/bin", name),
    }

    for _, p := range commonPaths {
        if _, err := os.Stat(p); err == nil {
            return p, nil
        }
    }

    return "", fmt.Errorf("tool %s not found", name)
}
```

### Anti-Pattern 2: Shared Mutable State

**What:** Global variables for configuration, pipeline state

**Why bad:** Breaks concurrency, makes testing hard, hides dependencies

**Instead:** Pass config/state explicitly via structs, use dependency injection

### Anti-Pattern 3: Swallowing Errors

**What:** `if err != nil { log.Println(err); continue }`

**Why bad:** Silent failures, debugging nightmares, corrupt state

**Instead:** Return errors, let caller decide (continue, abort, retry)

### Anti-Pattern 4: Tight Coupling to Tool Output Format

**What:** Parse tool JSON directly in pipeline logic

**Why bad:** Tool updates break pipeline, hard to test, violates SRP

**Instead:** Tool wrappers normalize to internal structs, pipeline works with abstractions

### Anti-Pattern 5: Blocking on Long Operations

**What:** Run nmap scan synchronously in main goroutine without progress feedback

**Why bad:** User sees frozen terminal for 20 minutes, no way to check progress

**Instead:** Run in goroutine, send progress updates via channel, display spinner/status

## Build Order Implications

### Critical Dependencies

The architecture reveals these **build dependencies** that must inform roadmap phase structure:

```
Layer 1 (Foundation):
  - internal/config (no dependencies)
  - internal/storage (no dependencies)

Layer 2 (Tool Integration):
  - internal/tools/* (depends on: config for options)

Layer 3 (Business Logic):
  - internal/pipeline (depends on: tools, storage)
  - internal/diff (depends on: storage)
  - internal/report (depends on: storage data models)

Layer 4 (Interface):
  - cmd/* (depends on: pipeline, config, diff, report)
```

### Suggested Build Order

**Why this order:**
1. **Storage first** - Defines data models that everything else references
2. **Config first** - Required by tools layer for execution options
3. **Tools before pipeline** - Pipeline orchestrates tools, can't exist without them
4. **Report after pipeline** - Needs pipeline data to generate output
5. **CLI last** - Integrates all other components

**Validation opportunity:** After Layer 2 (tools), can validate critical assumption: "Can we actually parse these tools' output?" Build parser tests with fixture data before building orchestration.

### Recommended Phase Structure

Based on component dependencies:

**Phase 1: Data Foundation**
- Implement `internal/storage/models.go` (Scan, Subdomain, Port, Vulnerability structs)
- Implement `internal/storage/bbolt.go` (basic Save/Get)
- Implement `internal/config/config.go` (viper-based config loading)
- **Why first:** Defines contracts for all other components
- **Validation:** Can we save/load a scan? Does bbolt handle our data size?

**Phase 2: Single Tool Integration**
- Implement ONE tool wrapper (e.g., `internal/tools/subfinder.go`)
- Write parser for that tool's JSON output
- Add unit tests with fixture data
- **Why second:** Validates we can exec tools and parse output before building orchestration
- **Risk mitigation:** If tool parsing is harder than expected, discover now
- **Validation:** Does subfinder JSON match our assumptions? Can we normalize it?

**Phase 3: Basic Pipeline Orchestrator**
- Implement `internal/pipeline/stage.go` (Stage interface)
- Implement `internal/pipeline/executor.go` (sequential execution only)
- Wire up single tool as proof-of-concept
- **Why third:** Now that we know tools work, build orchestration layer
- **Validation:** Can we chain Stage 1 → Stage 2?

**Phase 4: Reporting**
- Implement `internal/report/markdown.go`
- Add `text/template` files
- Generate report from storage data
- **Why fourth:** Once we have data flowing through pipeline, need output
- **Validation:** Are markdown reports readable? Do templates render correctly?

**Phase 5: CLI (Basic)**
- Implement `cmd/root.go` and `cmd/run.go`
- Hardcode pipeline to 2-3 stages
- Basic flag parsing (domain, output-dir)
- **Why fifth:** Now we can run end-to-end from CLI
- **Validation:** Full flow works? User experience acceptable?

**Phase 6: Advanced Pipeline**
- Add parallel execution support (errgroup)
- Implement resume logic (StateTracker)
- Add multiple tool wrappers
- **Why later:** These are enhancements, not core functionality

**Phase 7: Diff & Historical**
- Implement `internal/diff/differ.go`
- Implement `cmd/diff.go`
- Add dangling DNS detection
- **Why later:** Requires multiple scans to test, secondary feature

**Phase 8: Wizard Mode**
- Implement `cmd/wizard.go`
- Add promptui interactions
- Polish UX
- **Why last:** Interface sugar, core functionality must work first

### Critical Validation Points

**After Phase 2 (Tool Integration):**
- Question: "Can we parse all 9 tools' output formats?"
- Risk: Tool doesn't support JSON, or JSON schema undocumented
- Action: If blocker found, may need Phase 2b: "Build custom JSON translator"

**After Phase 3 (Pipeline):**
- Question: "Does stage chaining work? Can Stage N read Stage N-1's output?"
- Risk: Data normalization assumptions broken
- Action: If blocker found, revisit storage models

**After Phase 5 (CLI Basic):**
- Question: "Is end-to-end flow fast enough? Usable?"
- Risk: Performance issues, UX problems
- Action: If blocker found, may need performance optimization phase before adding features

### Parallel Work Opportunities

These components are **independent** and can be built in parallel:

- `internal/config` + `internal/storage` (Phase 1) - No dependencies on each other
- Different tool wrappers (Phase 2 expansion) - Each tool is independent
- `internal/diff` + `cmd/wizard` (Phases 7-8) - Independent features

**NOT parallel:**
- CLI cannot be built before pipeline (depends on it)
- Pipeline cannot be built before tools (orchestrates them)
- Report cannot be built before storage models (uses data structures)

## Scalability Considerations

| Concern | At 10 domains | At 100 domains | At 1000 domains |
|---------|---------------|----------------|-----------------|
| **Subdomain enumeration** | Sequential OK (< 1 min) | Parallel per domain (5-10 min) | Worker pool + rate limiting (30-60 min) |
| **Port scanning** | Full range per host | Top 1000 ports | Service-specific ports only, masscan instead of nmap |
| **Storage** | Filesystem JSON | bbolt (< 100MB) | Consider SQLite or sharded bbolt |
| **Memory** | Load all results in RAM | Stream parsing with bufio | Stream + flush to disk per stage |
| **Concurrency** | errgroup with GOMAXPROCS workers | Worker pool with configurable size | Semaphore-based limiting (e.g., 50 concurrent) |

**Note:** For 2-person team, "At 10 domains" is typical. Optimize for that, make others possible.

## Testing Strategy

### Unit Tests
- Tool wrappers with mocked commands (use exec.CommandContext stubbing)
- Diff logic with fixture data
- Markdown generation with golden files

### Integration Tests
- Run against test domains (e.g., scanme.nmap.org)
- Validate full pipeline with real tools (CI gate)
- Compare outputs with known-good results

### E2E Tests
- Use go-expect to simulate wizard interactions
- Run full pipeline, verify reports generated
- Test resume by killing midway and restarting

## Sources

**Confidence:** MEDIUM

**Based on:**
- Standard Go CLI architecture patterns (cobra + viper standard)
- Training data on Go concurrency patterns (errgroup, context)
- Common recon tool integration patterns
- CLI best practices (12-factor, clean architecture principles)

**Verification recommended:**
- Check latest cobra/viper architectural examples
- Review how ProjectDiscovery tools are architected (subfinder, nuclei are open source)
- Validate bbolt performance characteristics for expected data volumes

**Authoritative references:**
- Go CLI patterns: https://github.com/spf13/cobra (examples/ directory)
- Concurrency: https://go.dev/blog/context
- ProjectDiscovery architecture: https://github.com/projectdiscovery (any tool, internal/ structure)
