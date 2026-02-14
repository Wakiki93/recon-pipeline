# Technology Stack

**Project:** ReconPipe
**Researched:** 2026-02-14
**Overall Confidence:** MEDIUM (based on training data from January 2025, unable to verify with current sources)

## Recommended Stack

### Core CLI Framework
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **cobra** | v1.8+ | CLI framework, subcommands, flags | Industry standard for Go CLIs (kubectl, hugo, gh). Mature, well-documented, excellent flag handling. Better wizard support than alternatives. |
| **survey** | v2.3+ | Interactive prompts/wizards | Clean API for questions, validates input, handles wizard flows. Used by major CLIs (Kubernetes tools, terraform). |
| **viper** | v1.18+ | Configuration management | Pairs with cobra, handles config files + env vars + flags. Standard in Go ecosystem. |

**Confidence:** HIGH — cobra/viper/survey is the de facto standard for production Go CLIs.

### Process Orchestration
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **os/exec** | stdlib | Execute external tools | Native Go, no dependencies. Sufficient for sequential pipelines. |
| **golang.org/x/sync/errgroup** | latest | Parallel execution | Stdlib-adjacent, clean error handling for concurrent tool execution. |
| **github.com/creack/pty** | v1.1+ | PTY allocation (optional) | For tools requiring TTY. Only if subfinder/nuclei need interactive mode. |

**Confidence:** HIGH — os/exec + errgroup is standard practice. pty is niche but proven.

**Alternative (not recommended):** taskflow, go-cmd — adds complexity without clear benefits for this use case.

### Output Parsing
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **encoding/json** | stdlib | Parse JSON output | Most recon tools output JSON (subfinder -json, httpx -json). Native, fast. |
| **gopkg.in/yaml.v3** | v3.0+ | Parse YAML (if needed) | Some tools use YAML. v3 is current, v2 is deprecated. |
| **bufio.Scanner** | stdlib | Stream large outputs | Memory-efficient for nmap/nuclei with huge result sets. |

**Confidence:** HIGH — Native stdlib is sufficient. Recon tools mostly emit JSON or line-delimited text.

### Markdown Report Generation
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **github.com/yuin/goldmark** | v1.7+ | Markdown rendering (if HTML needed) | Reference implementation, extensible. But you likely just need text. |
| **text/template** | stdlib | Generate markdown files | Native, powerful, no deps. Markdown is just text — template it directly. |
| **github.com/olekukonko/tablewriter** | v0.0.5+ | ASCII/markdown tables | Clean table output for CLI and markdown reports. Widely used. |

**Confidence:** MEDIUM — text/template is sufficient for markdown generation. goldmark only needed if rendering to HTML. tablewriter is common but not critical (can template tables manually).

### Data Storage (Tracking & Diffs)
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **go.etcd.io/bbolt** | v1.3+ | Embedded key-value DB | Pure Go, single file, no server. Perfect for scan history and diffs. Used by etcd, Consul. |
| **encoding/gob** | stdlib | Serialize scan results | Native binary encoding. Fast, compact, type-safe for Go structs. |

**Confidence:** HIGH — bbolt is the standard embedded DB for Go CLIs. Alternative is SQLite (via mattn/go-sqlite3) but bbolt is simpler for key-value access patterns.

**Alternative (not recommended):** JSON files — fragile at scale, no transactional integrity for diffs.

### DNS & Network Utilities
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **github.com/miekg/dns** | v1.1+ | DNS queries, validation | De facto DNS library in Go. Used by CoreDNS, many recon tools. |
| **net** | stdlib | IP parsing, CIDR checks | Native, fast, comprehensive. |

**Confidence:** HIGH — miekg/dns is the DNS library for Go.

### Cross-Platform Support
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **runtime.GOOS/GOARCH** | stdlib | Platform detection | Native Go, compile-time and runtime detection. |
| **github.com/mitchellh/go-homedir** | v1.1+ | Cross-platform home dir | Handles ~/ expansion reliably across OS. |
| **golang.org/x/sys/execabs** | latest | PATH validation (security) | Prevents binary hijacking. Use instead of os/exec for production. |

**Confidence:** HIGH — stdlib handles most cross-platform needs. go-homedir is tiny and proven. execabs is security best practice (Go 1.19+).

### Logging & Debugging
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **log/slog** | stdlib (Go 1.21+) | Structured logging | New standard logger, structured output, levels, context. Replaces older log libs. |
| **github.com/fatih/color** | v1.16+ | Colorized output | Clean API, widely used. Makes wizard UX better. |

**Confidence:** HIGH — slog is the modern standard (if Go 1.21+). color is ubiquitous for CLI UX.

**Alternative:** zerolog, zap — faster but overkill for a CLI tool. slog is sufficient.

### Testing
| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| **testing** | stdlib | Unit tests | Native, table-driven tests work great. |
| **github.com/stretchr/testify** | v1.9+ | Assertions, mocking | Industry standard. assert, require, mock packages. |
| **github.com/Netflix/go-expect** | v0.0.0-20220104043353-73e0943537d2 | CLI integration tests | Simulate user input in wizard mode. Used by HashiCorp tools. |

**Confidence:** MEDIUM — testify is standard. go-expect is proven but less common (may need recent commit hash, not semver tagged).

## Installation

### Minimal Setup
```bash
# Initialize Go module
go mod init github.com/yourorg/reconpipe

# Core CLI
go get github.com/spf13/cobra@latest
go get github.com/spf13/viper@latest
go get github.com/AlecAivazis/survey/v2@latest

# Process & parsing (mostly stdlib)
go get golang.org/x/sync/errgroup@latest

# Storage
go get go.etcd.io/bbolt@latest

# DNS
go get github.com/miekg/dns@latest

# Utilities
go get github.com/fatih/color@latest
go get github.com/olekukonko/tablewriter@latest
go get github.com/mitchellh/go-homedir@latest
```

### Full Stack (with testing)
```bash
# Add testing tools
go get github.com/stretchr/testify@latest
go get github.com/Netflix/go-expect@latest
```

## What NOT to Use

| Technology | Why Avoid | Use Instead |
|------------|-----------|-------------|
| **urfave/cli** | Less ergonomic than cobra for complex subcommands. Wizard mode harder to implement. | cobra + survey |
| **kingpin** | Abandoned, no updates since 2019. | cobra |
| **go-cmd** | Overcomplicated for simple exec. Adds async complexity you don't need. | os/exec + errgroup |
| **gopsutil** | Overkill for process orchestration. Heavy dependency for simple exec. | os/exec |
| **logrus** | De facto deprecated. Not structured by default. | log/slog (Go 1.21+) |
| **JSON files for scan history** | No transactions, race conditions, fragile at scale. | bbolt or SQLite |
| **HTML templating for markdown** | Markdown is text. Don't overcomplicate. | text/template |

## Rationale Summary

**CLI Framework:** cobra is the industry standard. kubectl, hugo, github CLI all use it. Mature, excellent docs, active maintenance.

**Wizards:** survey is the clean choice. Handles validation, multi-select, confirms. Better UX than raw fmt.Scanln.

**Process Execution:** os/exec + errgroup is sufficient. This is a sequential pipeline with optional parallelization. Don't introduce async complexity prematurely.

**Parsing:** Most recon tools emit JSON. encoding/json is fast and native. bufio.Scanner for streaming large outputs (nmap XML, nuclei findings).

**Markdown Generation:** It's just text. text/template is powerful and native. goldmark only if you need HTML rendering later.

**Storage:** bbolt for scan history and diffs. Pure Go, embedded, transactional. SQLite is heavier and requires cgo.

**Logging:** slog (Go 1.21+) is the modern standard. Structured, leveled, context-aware. If Go <1.21, use zerolog.

**Cross-Platform:** Go's stdlib handles most. execabs prevents PATH hijacking. go-homedir for ~/ expansion.

## Version Notes

**Go Version:** Recommend Go 1.21+ for log/slog. If stuck on older Go, use zerolog instead.

**Dependency Management:** Use `go mod tidy` and commit `go.sum`. Pin versions in production.

**Security:** Use golang.org/x/sys/execabs instead of os/exec to prevent binary hijacking. Validate tool paths before execution.

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| CLI Framework | cobra | urfave/cli | Less ergonomic for subcommands, harder wizard integration |
| CLI Framework | cobra | kingpin | Abandoned (no updates since 2019) |
| Prompts | survey | promptui | survey has better validation and multi-select UX |
| Storage | bbolt | SQLite (mattn/go-sqlite3) | bbolt is pure Go (no cgo), simpler for key-value patterns |
| Storage | bbolt | JSON files | No transactions, race conditions, fragile |
| Logging | slog | logrus | logrus deprecated, slog is modern standard |
| Logging | slog | zap/zerolog | Faster but overkill for CLI, slog sufficient |
| Markdown | text/template | goldmark | goldmark is for rendering, not generation. Markdown is text. |
| Process exec | os/exec + errgroup | go-cmd | go-cmd adds async complexity without clear benefit |

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| CLI Framework (cobra/viper/survey) | **HIGH** | Industry standard, proven in production CLIs (kubectl, gh, hugo) |
| Process Orchestration (os/exec + errgroup) | **HIGH** | Stdlib + official x/sync, standard practice |
| Parsing (encoding/json) | **HIGH** | Native stdlib, recon tools emit JSON |
| Markdown Generation (text/template) | **MEDIUM** | Stdlib sufficient, but could verify if specialized libs exist |
| Storage (bbolt) | **HIGH** | Standard embedded DB for Go CLIs (etcd, consul use it) |
| DNS (miekg/dns) | **HIGH** | De facto DNS library in Go (used by CoreDNS) |
| Logging (slog) | **HIGH** | New stdlib standard (Go 1.21+) |
| Testing (testify) | **HIGH** | Industry standard assertions/mocking |
| Cross-platform (stdlib + execabs) | **HIGH** | Stdlib + security best practice |

## Sources

**Limitation:** Unable to access Context7 or WebSearch in this environment. Recommendations based on training data (knowledge cutoff January 2025).

**Verification needed:**
- Latest cobra/viper/survey versions (recommended: check GitHub releases)
- Go 1.23/1.24 compatibility (training data current to Go 1.22)
- Any new stdlib improvements in Go 1.23+ (e.g., enhanced slog features)

**Authoritative sources for verification:**
- cobra: https://github.com/spf13/cobra
- viper: https://github.com/spf13/viper
- survey: https://github.com/AlecAivazis/survey
- bbolt: https://github.com/etcd-io/bbolt
- miekg/dns: https://github.com/miekg/dns
- Go blog (stdlib updates): https://go.dev/blog/

**Recommended verification:** Check GitHub stars/activity and release dates for survey and tablewriter (less critical deps) to ensure no abandonment.
