# ReconPipe

A command-line recon pipeline that chains together the best open-source security tools into a single, repeatable workflow. Point it at a domain and it will find subdomains, scan ports, probe HTTP services, detect vulnerabilities, and show you what changed since your last scan.

---

## What It Does

ReconPipe runs five stages in order:

```
discover → portscan → probe → vulnscan → diff
```

| Stage | What happens |
|-------|-------------|
| **discover** | Finds subdomains using subfinder + TLS certificates, resolves DNS, flags dangling records |
| **portscan** | Filters out CDN IPs, runs masscan to find open ports, nmap for service versions |
| **probe** | Hits every HTTP/HTTPS service with httpx, captures screenshots with gowitness |
| **vulnscan** | Runs nuclei templates against all discovered targets, generates PDF report |
| **diff** | Compares current scan to the previous one — shows new subdomains, opened ports, new vulns |

Everything is saved to a timestamped folder under `scans/`. Each stage writes structured JSON (for automation) and a markdown report (for humans).

---

## Requirements

### Go
You need Go 1.21 or later. Download at https://go.dev/dl/

### External Tools

Install all of these before running a scan:

**Required:**

| Tool | Install |
|------|---------|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| nmap | https://nmap.org/download.html |
| masscan | `apt install masscan` / `brew install masscan` |
| dig | `apt install dnsutils` / `brew install bind` |

**Optional (gracefully skipped if missing):**

| Tool | What you lose without it | Install |
|------|--------------------------|---------|
| tlsx | TLS certificate subdomain discovery | `go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| cdncheck | CDN IP filtering (may scan Cloudflare IPs) | `go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` |
| gowitness | Screenshots of live HTTP services | `go install github.com/sensepost/gowitness@latest` |

> **Windows users:** Make sure `C:\Users\<you>\go\bin` and your nmap/dig directories are in your PATH. After installing, open a new terminal for PATH changes to take effect.

---

## Installation

```bash
git clone https://github.com/Wakiki93/recon-pipeline
cd recon-pipeline
go build -o reconpipe ./cmd/reconpipe
```

On Windows:
```powershell
git clone https://github.com/Wakiki93/recon-pipeline
cd recon-pipeline
go build -o reconpipe.exe ./cmd/reconpipe
```

---

## Quick Start

**1. Initialize** (creates config file and database):
```bash
./reconpipe init
```

**2. Check your tools** (make sure everything is installed):
```bash
./reconpipe check
```

**3. Run your first scan:**
```bash
./reconpipe scan -d example.com --preset quick-recon
```

That's it. Results land in `scans/example.com_<timestamp>/`.

---

## Presets

Presets are the easiest way to control what gets run.

| Preset | Stages | Best for |
|--------|--------|----------|
| `quick-recon` | discover + portscan | Fast surface mapping, ~5 minutes |
| `bug-bounty` | all 5 stages, critical/high/medium vulns | Bug bounty programs |
| `internal-pentest` | all 5 stages, includes low severity | Internal network assessments |

```bash
./reconpipe scan -d example.com --preset quick-recon
./reconpipe scan -d example.com --preset bug-bounty
./reconpipe scan -d example.com --preset internal-pentest
```

---

## Commands

### `scan` — Run the full pipeline

```bash
./reconpipe scan -d example.com [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --domain` | required | Target domain |
| `--preset` | — | Named preset: `quick-recon`, `bug-bounty`, `internal-pentest` |
| `--stages` | all | Only run specific stages: `discover,portscan` |
| `--skip` | — | Skip specific stages: `vulnscan,diff` |
| `--severity` | `critical,high,medium` | Nuclei severity filter |
| `--timeout` | `2h` | Total time limit for the entire run |
| `--resume` | false | Pick up where a crashed scan left off |
| `--scan-dir` | auto | Reuse an existing scan directory |
| `--scope-domains` | — | Limit to specific domains: `"example.com,*.example.com"` |
| `--skip-pdf` | false | Skip PDF report generation |
| `--notify-webhook` | — | POST a summary to this URL when done |

**Examples:**
```bash
# Full bug bounty scan
./reconpipe scan -d example.com --preset bug-bounty

# Run only discovery with a 10 minute limit
./reconpipe scan -d example.com --stages discover --timeout 10m

# Skip screenshots and PDF to go faster
./reconpipe scan -d example.com --preset bug-bounty --skip-pdf

# Resume a scan that crashed
./reconpipe scan -d example.com --resume

# Scope to a specific subdomain pattern
./reconpipe scan -d example.com --scope-domains "example.com,*.example.com"
```

---

### `check` — Verify tool installation

```bash
./reconpipe check
```

Shows the status of all 9 external tools with version info and install commands for any that are missing.

---

### `history` — View past scans

```bash
./reconpipe history -d example.com
./reconpipe history -d example.com --limit 20
```

Shows a table of all scans for a domain: scan ID, date, status, and which stages completed.

---

### `diff` — Compare two scans

```bash
# Auto-compare latest vs second-latest
./reconpipe diff -d example.com

# Compare against a specific previous scan directory
./reconpipe diff -d example.com --compare scans/example.com_20260101_120000
```

Shows what changed: new subdomains, removed subdomains, newly opened ports, closed ports, new vulnerabilities, and resolved vulnerabilities.

---

### Run individual stages

You can run stages one at a time instead of using `scan`:

```bash
# Stage 1: Find subdomains
./reconpipe discover -d example.com

# Stage 2: Scan ports (reads subdomains.json from stage 1)
./reconpipe portscan -d example.com

# Stage 3: Probe HTTP services
./reconpipe probe -d example.com

# Stage 4: Scan for vulnerabilities
./reconpipe vulnscan -d example.com --severity critical,high

# Stage 5: Generate diff report
./reconpipe diff -d example.com
```

Each stage auto-detects the latest scan directory for the domain and reads its predecessor's output.

---

## Output Structure

Every scan creates a folder like `scans/example.com_20260224_143022/`:

```
scans/
  example.com_20260224_143022/
    raw/
      subdomains.json       - All discovered subdomains with DNS data
      ports.json            - Open ports with service versions
      http-probes.json      - Live HTTP services with metadata
      vulns.json            - Discovered vulnerabilities
      nuclei-output.jsonl   - Raw nuclei output (for other tools)
      diff.json             - What changed since last scan
    reports/
      subdomains.md         - Subdomain report
      ports.md              - Port scan report
      http-probes.md        - HTTP services report
      vulns.md              - Vulnerability report
      vulns.pdf             - PDF vulnerability report
      diff.md               - Change summary
      dangling-dns.md       - Dangling DNS security risks
    screenshots/
      *.png                 - Screenshots from gowitness
```

The `raw/` JSON files are machine-readable and suitable for feeding into other tools or scripts. The `reports/` markdown files are human-readable summaries.

---

## Configuration

`reconpipe.yaml` is created by `reconpipe init`. Key settings:

```yaml
# Where scan folders are created
scan_dir: scans

# Database file for scan history
db_path: reconpipe.db

# Rate limits — tune these for your environment
rate_limits:
  subfinder_threads: 10
  masscan_rate: 1000       # packets/second — lower if you're on a slow network
  nmap_max_parallel: 5
  httpx_threads: 25
  nuclei_threads: 10
  nuclei_rate_limit: 150

# Custom binary paths — useful if tools aren't in your PATH
tools:
  nmap:
    path: /usr/bin/nmap
  masscan:
    path: /usr/bin/masscan
```

---

## Tips

**Slow network or shared environment?** Lower the masscan rate:
```yaml
rate_limits:
  masscan_rate: 100
```

**Want only critical findings?**
```bash
./reconpipe scan -d example.com --severity critical
```

**Running on a schedule?** Use `--notify-webhook` to POST results to Slack, Discord, or any HTTP endpoint when a scan finishes:
```bash
./reconpipe scan -d example.com --preset bug-bounty --notify-webhook https://hooks.slack.com/...
```

**Track changes over time** by running scans regularly and using `diff`:
```bash
./reconpipe scan -d example.com --preset quick-recon
# ...a week later...
./reconpipe scan -d example.com --preset quick-recon
./reconpipe diff -d example.com   # shows what's new
```

---

## Legal

Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. `scanme.nmap.org` is available as a safe test target (Nmap explicitly permits scanning it).

---

## Tech Stack

- **Go** — CLI, pipeline orchestration, all data processing
- **[Cobra](https://github.com/spf13/cobra)** — CLI framework
- **[Viper](https://github.com/spf13/viper)** — Config file parsing
- **[bbolt](https://github.com/etcd-io/bbolt)** — Embedded database for scan history
- **[ProjectDiscovery](https://github.com/projectdiscovery)** — subfinder, httpx, tlsx, cdncheck, nuclei
- **[Nmap](https://nmap.org)** — Service fingerprinting
- **[masscan](https://github.com/robertdavidgraham/masscan)** — Fast port discovery
- **[gowitness](https://github.com/sensepost/gowitness)** — Web screenshots
