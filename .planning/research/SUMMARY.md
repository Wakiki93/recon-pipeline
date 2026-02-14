# Project Research Summary

**Project:** ReconPipe
**Domain:** Security reconnaissance automation CLI
**Researched:** 2026-02-14
**Confidence:** MEDIUM

## Executive Summary

ReconPipe is a security reconnaissance pipeline orchestrator that automates the execution of multiple tools (subfinder, httpx, nuclei, nmap) for external penetration testing. Based on research, the recommended approach is a Go CLI using the standard cobra/viper stack with direct process execution and structured output. The tool should prioritize robust process lifecycle management, markdown-based reporting, and diff capabilities for continuous monitoring.

The core value proposition is orchestrating existing tools reliably rather than reimplementing functionality. Experts in this domain favor single-binary CLIs with wizard modes for beginners and pipe-friendly flags for power users. The killer feature based on research is diff mode ("what changed since last scan?") combined with dangling DNS detection, which addresses a gap in existing tools like reconftw and reNgine that focus on initial enumeration without change tracking.

The primary risks are zombie process accumulation (tools spawning orphaned children), output parser brittleness (tools update frequently, breaking parsers), and rate limit cascade failures (API bans mid-scan). These can be mitigated through process group management, JSON-only parsing with validation, and centralized rate limiting. The architecture must prioritize these concerns in the foundation phase rather than retrofitting later.

## Key Findings

### Recommended Stack

Go provides the ideal foundation for this domain. The cobra/viper/survey combination is the industry standard for CLI tools (used by kubectl, gh, hugo), offering excellent subcommand handling and wizard support. Process orchestration uses native os/exec with golang.org/x/sync/errgroup for parallelization, avoiding unnecessary complexity.

**Core technologies:**
- **cobra + viper + survey**: CLI framework, config, and interactive prompts — de facto standard, proven in production CLIs
- **bbolt**: Embedded key-value database for scan history — pure Go, single file, transactional (used by etcd)
- **os/exec + errgroup**: Process execution and parallel coordination — stdlib sufficient, no need for complex async libs
- **encoding/json + bufio.Scanner**: Parse tool output — most recon tools support JSON mode, stream large outputs
- **text/template**: Markdown report generation — markdown is text, don't overcomplicate with HTML rendering
- **log/slog**: Structured logging (Go 1.21+) — modern stdlib standard for leveled, context-aware logs
- **miekg/dns**: DNS queries and validation — de facto DNS library in Go (used by CoreDNS)

**What NOT to use:**
- urfave/cli or kingpin (cobra is more ergonomic)
- JSON files for scan history (bbolt provides transactions, prevents race conditions)
- HTML templating for markdown (overengineered)
- logrus (deprecated, slog is modern standard)

### Expected Features

**Must have (table stakes):**
- Multi-stage pipeline orchestration (subfinder → httpx → nuclei sequence)
- Subdomain enumeration (via subfinder)
- Live host detection (via httpx)
- Vulnerability scanning (nuclei integration expected by community)
- Output organization (per-target folders, timestamped)
- Resume failed runs (scans crash, network fails)
- Deduplication (same subdomain from multiple sources)
- Logging and progress indication (scans take hours)
- Configuration file (YAML/JSON for tool parameters)

**Should have (competitive differentiators):**
- **Diff mode** (killer feature: "what changed since last week?") — critical for continuous monitoring
- **Dangling DNS tracking** (high-value finding: subdomain takeover detection)
- **Wizard mode** (interactive prompts lower barrier to entry)
- **Pipe-friendly** (read stdin, write stdout, chainable for power users)
- **Markdown reports per stage** (readable, shareable, version-controllable)
- **Cross-platform binary** (Linux, macOS, WSL without Docker)
- **Selective stage execution** ("just run nuclei on existing httpx output")
- **Scope validation** (prevent scanning out-of-scope targets — legal risk mitigation)

**Defer (v2+):**
- Notification hooks (Slack/Discord on completion)
- Cost estimation (pre-flight analysis of scan duration)
- Template/preset workflows ("bug bounty mode", "internal pentest mode")
- Single binary with embedded tools (start with "tools in PATH" requirement)

**Explicitly DO NOT build:**
- Web GUI/dashboard (complexity explosion, not needed for 2-person team)
- Database storage (filesystem is simpler, grep-able, git-friendly)
- Built-in exploit modules (legal risk, scope creep)
- Multi-user/collaboration features (team is 2 people)
- Custom vulnerability scanner (nuclei exists)

### Architecture Approach

The recommended architecture follows standard Go CLI patterns with clear component boundaries: cmd/ layer handles CLI interface and routing, internal/pipeline orchestrates stage execution, internal/tools wraps external binaries with standardized interfaces, internal/storage manages scan history via bbolt, and internal/report generates markdown outputs. Data flows sequentially through stages with intermediate persistence after each stage to enable resume capability.

**Major components:**
1. **cmd/**: CLI interface using cobra (run, diff, wizard subcommands) — routes user input to pipeline
2. **internal/pipeline**: Stage orchestration with context-based cancellation — chains tool execution, manages state
3. **internal/tools**: External tool wrappers (one per tool: subfinder.go, httpx.go, nuclei.go) — isolates parsing logic, normalizes output
4. **internal/storage**: bbolt-backed persistence with gob serialization — tracks scan history for diffs, enables resume
5. **internal/report**: Markdown generation via text/template — produces per-stage reports
6. **internal/diff**: Scan comparison and dangling DNS detection — queries storage for historical data

**Key patterns:**
- Stage interface (uniform Run/Validate contract)
- Tool wrapper pattern (isolate exec + parsing per tool)
- Storage abstraction (decouple bbolt from business logic)
- Context-based cancellation (clean shutdown on Ctrl+C)
- Idempotent stages (track completion for resume)

**Critical dependencies for build order:**
- Storage + Config first (define data models and contracts)
- Tools second (pipeline depends on these)
- Pipeline third (orchestrates tools)
- Report + Diff fourth (consume pipeline data)
- CLI last (integrates all components)

### Critical Pitfalls

1. **Zombie process accumulation** — External tools spawn child processes that outlive parent. Go's exec.Command doesn't auto-kill children. Use process groups (Setpgid) and syscall.Kill with negative PID to kill entire group. Missing this causes PID exhaustion and system resource drain. MUST address in foundation phase.

2. **Output parser brittleness** — Security tools change output format in minor versions, breaking parsers silently. Pipeline reports zero findings instead of errors. Use JSON-only output modes (-json flags), validate parsed output (empty result with non-empty raw output = warning), fail loudly on parse errors. Version-pin tools in documentation.

3. **Rate limiting cascade failures** — Pipeline hammers APIs (Shodan, DNS resolvers) without backoff, gets banned mid-scan. Subsequent stages fail. Implement centralized rate limiter tracking cumulative usage across tools, fail fast on rate limit errors rather than continuing with partial data.

4. **Output file chaos** — Tools output to scattered temp directories with inconsistent naming. Can't correlate results, can't diff scans. Use structured directories (scans/domain_timestamp/01-subfinder.json, 02-httpx.json, manifest.json). Atomic writes (write to .tmp, rename on success).

5. **Cross-platform path assumptions** — Hardcoded /tmp and /usr/bin paths break on Windows/WSL. Use os.TempDir(), filepath.Join(), exec.LookPath() to find tools in PATH. Test on Windows, macOS, Linux.

## Implications for Roadmap

Based on research, suggested phase structure organized by dependencies and risk:

### Phase 1: Data Foundation & Single Tool Proof-of-Concept
**Rationale:** Must define data models first (everything references these). Validate critical assumption ("can we parse tool output?") before building orchestration. De-risks integration complexity early.

**Delivers:**
- Data models (Scan, Subdomain, Port, Vulnerability structs)
- bbolt storage (Save/Get scan operations)
- Config loading (viper-based YAML config)
- ONE tool wrapper (subfinder.go) with JSON parser
- Unit tests with fixture data

**Addresses Features:**
- Output organization (defines structure)
- Configuration file (viper setup)

**Avoids Pitfalls:**
- Output parser brittleness (validates JSON parsing works)
- Output file chaos (defines directory structure)

**Research Flag:** SKIP — storage and config patterns are well-documented in Go ecosystem.

---

### Phase 2: Basic Pipeline Orchestrator
**Rationale:** Now that we know tool parsing works (Phase 1 validation), build orchestration layer. Sequential execution only initially. Proves end-to-end flow before adding complexity.

**Delivers:**
- Stage interface (uniform contract)
- Sequential executor (errgroup-based)
- Wire up subfinder → httpx (2 stages)
- Context-based cancellation
- Process group management (anti-zombie)

**Addresses Features:**
- Multi-stage pipeline orchestration (core value prop)
- Progress indication (log stage transitions)

**Avoids Pitfalls:**
- Zombie process accumulation (process groups from day 1)
- Timeout mismanagement (context cancellation)

**Research Flag:** SKIP — cobra + context patterns are standard.

---

### Phase 3: Markdown Reporting & CLI (MVP)
**Rationale:** With data flowing through pipeline, add output layer. Make tool usable from CLI. This is minimum viable product — can run recon scans end-to-end.

**Delivers:**
- Markdown generation (text/template)
- Per-stage reports (subdomains.md, live-hosts.md)
- Basic CLI (cmd/run.go with flags)
- Error handling (log failures, don't crash)

**Addresses Features:**
- Markdown reports (differentiator)
- Logging (structured output)

**Avoids Pitfalls:**
- Progress opacity (streaming logs)
- Markdown report fragility (escape special chars)

**Research Flag:** SKIP — templating is straightforward.

---

### Phase 4: Diff Mode & Dangling DNS (Differentiators)
**Rationale:** Core competitive features identified in research. High value, medium complexity. Requires storage from Phase 1. Sets tool apart from reconftw/reNgine.

**Delivers:**
- Scan comparison (domain-level diff)
- Dangling DNS detection (NXDOMAIN + CNAME)
- cmd/diff subcommand
- Highlight new/removed findings

**Addresses Features:**
- Diff mode (killer feature for continuous monitoring)
- Dangling DNS tracking (high-value finding)

**Avoids Pitfalls:**
- Output file chaos (relies on structured storage)

**Research Flag:** NEEDED — Diff algorithms and "meaningful change" definition need design research. What constitutes a significant change? How to present diffs clearly?

---

### Phase 5: Additional Tool Integrations
**Rationale:** Expand from 2 tools to full suite (nmap, nuclei, etc.). Apply patterns from Phase 1-2 (tool wrapper, stage interface). Parallel execution within stages.

**Delivers:**
- Port scanning (nmap/masscan wrapper)
- Vulnerability scanning (nuclei wrapper)
- Parallel execution (errgroup per stage)
- Rate limiting (centralized limiter)

**Addresses Features:**
- Port scanning (table stakes)
- Vulnerability scanning (expected by community)

**Avoids Pitfalls:**
- Rate limiting cascade failures (central limiter)
- Tool duplication (clear boundaries: subfinder=discovery, nuclei=vuln)
- Timeout mismanagement (per-tool configurable timeouts)

**Research Flag:** NEEDED for nuclei — Template selection strategy, severity filtering, false positive handling need investigation.

---

### Phase 6: Resume Capability & Scope Validation
**Rationale:** Production-ready features. Resume is critical for long scans (real-world need). Scope validation prevents legal disasters.

**Delivers:**
- State tracking (completed stages)
- Idempotent stage execution
- Scope validation (CIDR/domain allowlist)
- Cloud provider detection (warn on AWS/GCP targets)

**Addresses Features:**
- Resume failed runs (table stakes for production)
- Scope validation (safety feature)

**Avoids Pitfalls:**
- No graceful degradation (save partial results)
- Target validation neglect (legal risk)

**Research Flag:** SKIP — state management patterns are standard.

---

### Phase 7: Wizard Mode & UX Polish
**Rationale:** Lower barrier to entry. Survey library integration. User-facing polish after core functionality proven.

**Delivers:**
- cmd/wizard.go (interactive prompts)
- Survey-based questions
- Input validation
- Colorized output (fatih/color)

**Addresses Features:**
- Wizard mode (beginner-friendly)
- Pipe-friendly (preserve flag-based mode for power users)

**Avoids Pitfalls:**
- Progress opacity (better UX feedback)
- Missing dependency checks (preflight validation)

**Research Flag:** SKIP — survey examples are well-documented.

---

### Phase Ordering Rationale

- **Foundation first (Phase 1):** Storage and config define contracts for all other components. Tool wrapper proof-of-concept de-risks integration assumptions before building orchestration.

- **Pipeline before CLI (Phase 2-3):** Can't build useful CLI without working pipeline. Sequential progression validates architecture before adding features.

- **Differentiators early (Phase 4):** Diff mode and dangling DNS are unique value. Get these working while codebase is small and malleable.

- **Tool expansion mid-project (Phase 5):** Apply proven patterns from Phases 1-2 to additional tools. Parallel execution added after sequential works.

- **Production features late (Phase 6-7):** Resume and wizard are polish, not core functionality. Build after MVP proves viable.

**Dependency chain:**
```
Phase 1 (Storage + Config + Tool Wrapper)
  ↓
Phase 2 (Pipeline Orchestrator) — depends on Phase 1 data models
  ↓
Phase 3 (Reports + CLI) — depends on Phase 2 pipeline
  ↓
Phase 4 (Diff Mode) — depends on Phase 1 storage
  ↓
Phase 5 (More Tools) — depends on Phase 2 patterns
  ↓
Phase 6 (Resume + Scope) — depends on Phase 2 state tracking
  ↓
Phase 7 (Wizard) — depends on Phase 3 CLI
```

**Parallel work opportunities:**
- Phase 1: Storage and Config are independent (can split)
- Phase 5: Each tool wrapper is independent (can parallelize)
- Phase 6-7: Resume and Wizard are independent features

### Research Flags

**Phases needing deeper research during planning:**

- **Phase 4 (Diff Mode):** Needs design research on diff algorithms, change significance criteria, and presentation format. Questions: What changes matter to pentesters? How to handle schema evolution? What's the optimal diff output format?

- **Phase 5 (Nuclei Integration):** Complex tool with 5,000+ templates. Need research on template selection strategy (tags? severity?), false positive handling, and severity filtering. Default to critical/high only or run all?

**Phases with standard patterns (skip research-phase):**

- **Phase 1:** Storage (bbolt examples), config (viper docs), JSON parsing (stdlib)
- **Phase 2:** Pipeline orchestration (cobra examples, errgroup patterns)
- **Phase 3:** Markdown templating (text/template docs)
- **Phase 6:** State tracking (standard Go patterns)
- **Phase 7:** Survey library (well-documented examples)

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | cobra/viper/bbolt are industry standard, proven in production CLIs. Extensive documentation and examples available. |
| Features | MEDIUM | Based on training data for reconftw/reNgine/ProjectDiscovery tools through Jan 2025. Unable to verify current community priorities. Pentester workflow understanding is strong. |
| Architecture | HIGH | Standard Go CLI patterns (cobra + clean architecture). Component boundaries are well-established. ProjectDiscovery tools use similar structure. |
| Pitfalls | MEDIUM | Process management and cross-platform issues are well-documented. Security tool-specific pitfalls (rate limiting, parsing) based on training data, not live verification. |

**Overall confidence:** MEDIUM

### Gaps to Address

**Gap 1: Tool output format stability** — Research based on training data through Jan 2025. Tools like subfinder, httpx, nuclei may have changed JSON schemas. **Handle during Phase 1:** Build parser with fixture data from current tool versions. Add schema validation to detect breaking changes.

**Gap 2: API rate limits** — Third-party service limits (Shodan, SecurityTrails, VirusTotal) may have changed. **Handle during Phase 5:** Document current limits in README. Add configurable rate limits with conservative defaults.

**Gap 3: Nuclei template ecosystem** — 5,000+ templates as of training data, may have grown. Template organization and defaults unknown. **Handle during Phase 5 research:** Review nuclei documentation for current template categories and recommended subsets.

**Gap 4: Cross-platform tool availability** — Uncertain which recon tools support Windows natively vs requiring WSL. **Handle during Phase 1:** Document per-tool platform support. Test on Windows, macOS, Linux during proof-of-concept.

**Gap 5: Performance characteristics at scale** — Training data lacks empirical data on bbolt performance with large scan histories (100+ scans, 50k+ subdomains). **Handle during Phase 1:** Load test with synthetic data. Establish limits in documentation.

## Sources

### Primary (HIGH confidence)
- Go CLI patterns: cobra/viper/survey library documentation (standard patterns, stable APIs)
- Go stdlib: os/exec, context, text/template documentation (official, well-established)
- bbolt architecture: etcd-io/bbolt repository and docs (proven embedded DB)

### Secondary (MEDIUM confidence)
- ProjectDiscovery tool ecosystem (subfinder, httpx, nuclei) — training data through Jan 2025, unable to verify current versions
- Recon automation tools (reconftw, reNgine, Osmedeus) — feature comparison based on training data
- Pentester workflow patterns — general industry practices, not primary research

### Tertiary (LOW confidence)
- Current API rate limits for third-party services — needs validation
- Latest tool output formats — needs verification with current versions
- Nuclei template organization (2026) — may have evolved since training data

### Research Limitations
WebSearch and Context7 were unavailable during research. Findings based on training data (knowledge cutoff January 2025). Key claims about tool output formats, API limits, and community priorities should be validated during implementation against current documentation and tool versions.

---
*Research completed: 2026-02-14*
*Ready for roadmap: yes*
