package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/diff"
	"github.com/hakim/reconpipe/internal/discovery"
	"github.com/hakim/reconpipe/internal/httpprobe"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/pipeline"
	"github.com/hakim/reconpipe/internal/portscan"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
	"github.com/hakim/reconpipe/internal/vulnscan"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run the full recon pipeline in a single command",
	Long: `Run the complete reconnaissance pipeline for a target domain.

Executes all five stages in order — discover, portscan, probe, vulnscan, diff —
using a single scan directory.  Stages can be filtered, skipped, or selected via
a named preset.  The run can be resumed after a crash with --resume.

Results are saved to:
  {scan_dir}/{target}_{timestamp}/raw/          (structured JSON per stage)
  {scan_dir}/{target}_{timestamp}/reports/      (markdown and optional PDF)

Scan metadata is persisted to the configured database so history and diff work
across runs.

Examples:
  reconpipe scan -d example.com
  reconpipe scan -d example.com --preset bug-bounty
  reconpipe scan -d example.com --stages discover,portscan
  reconpipe scan -d example.com --resume
  reconpipe scan -d example.com --scope-domains "example.com,*.example.com"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// ── 1. Read all flags ──────────────────────────────────────────────────
		domain, _ := cmd.Flags().GetString("domain")
		scanDir, _ := cmd.Flags().GetString("scan-dir")
		stagesFlag, _ := cmd.Flags().GetString("stages")
		skipFlag, _ := cmd.Flags().GetString("skip")
		resume, _ := cmd.Flags().GetBool("resume")
		presetName, _ := cmd.Flags().GetString("preset")
		severity, _ := cmd.Flags().GetString("severity")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		webhookURL, _ := cmd.Flags().GetString("notify-webhook")
		scopeDomainsFlag, _ := cmd.Flags().GetString("scope-domains")
		skipPDF, _ := cmd.Flags().GetBool("skip-pdf")

		// ── 2. Config check ────────────────────────────────────────────────────
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// ── 3. Apply preset (flags override preset values) ────────────────────
		var stageList []string
		var skipList []string

		if presetName != "" {
			preset, err := pipeline.GetPreset(presetName)
			if err != nil {
				return err
			}
			fmt.Printf("[*] Using preset: %s — %s\n", preset.Name, preset.Description)

			// Preset provides defaults; explicit flags take precedence.
			stageList = preset.Stages
			if severity == "critical,high,medium" {
				// Only apply preset severity when the user left it at the default.
				severity = preset.Severity
			}
			if !cmd.Flags().Changed("skip-pdf") {
				skipPDF = preset.SkipPDF
			}
		}

		// Parse --stages and --skip flags, overriding any preset values.
		if stagesFlag != "" {
			stageList = splitCSV(stagesFlag)
		}
		if skipFlag != "" {
			skipList = splitCSV(skipFlag)
		}

		// ── 4. Scope validation ────────────────────────────────────────────────
		if scopeDomainsFlag != "" {
			scopeCfg := pipeline.ScopeConfig{
				AllowedDomains: splitCSV(scopeDomainsFlag),
			}
			if err := scopeCfg.ValidateTarget(domain); err != nil {
				return fmt.Errorf("scope check failed: %w", err)
			}
			fmt.Printf("[*] Scope validated: %s is in scope\n", domain)
		}

		// ── 5. Pre-flight tool checks ──────────────────────────────────────────
		// Check all tools upfront so we fail fast before creating any directories.
		toolCheckResults := checkAllScanTools()
		printToolCheckSummary(toolCheckResults)

		// Hard-fail if any required tool is missing.
		for _, r := range toolCheckResults {
			if r.required && !r.found {
				return fmt.Errorf("required tool %q not found — install with: %s", r.name, r.installCmd)
			}
		}

		// Resolve availability of optional tools.
		tlsxAvailable := toolCheckResults["tlsx"].found
		cdncheckAvailable := toolCheckResults["cdncheck"].found
		gowitnessAvailable := toolCheckResults["gowitness"].found
		nucleiAvailable := toolCheckResults["nuclei"].found

		// Python is needed only for PDF generation.
		python3Available, pythonBinary := false, ""
		if !skipPDF {
			python3Available, pythonBinary = detectPython()
			if !python3Available {
				fmt.Println("[!] Warning: python3/python not found — PDF generation will be skipped")
			}
		}

		// ── 6. Open bbolt store ────────────────────────────────────────────────
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer store.Close()

		// ── 7. Build stage closures ────────────────────────────────────────────
		// Each closure is fully self-contained: it reads its inputs from disk and
		// writes its outputs to disk.  No Go variables are shared between stages.

		discoverStage := pipeline.Stage{
			Name: "discover",
			Run: func(ctx context.Context, scanDir string) error {
				// Ensure subdirectories exist (orchestrator creates scanDir but
				// not raw/ and reports/ when an existing scanDir is supplied).
				if err := storage.EnsureDir(filepath.Join(scanDir, "raw")); err != nil {
					return fmt.Errorf("ensuring raw dir: %w", err)
				}
				if err := storage.EnsureDir(filepath.Join(scanDir, "reports")); err != nil {
					return fmt.Errorf("ensuring reports dir: %w", err)
				}

				discoveryCfg := discovery.DiscoveryConfig{
					SubfinderThreads: cfg.RateLimits.SubfinderThreads,
					SubfinderPath:    "",
					TlsxPath:         "",
					DigPath:          "",
					SkipTlsx:         !tlsxAvailable,
				}

				result, err := discovery.RunDiscovery(ctx, domain, discoveryCfg)
				if err != nil {
					return fmt.Errorf("discovery pipeline: %w", err)
				}

				fmt.Printf("    [>] Found %d unique subdomains (%d resolved, %d dangling)\n",
					result.UniqueCount, result.ResolvedCount, result.DanglingCount)

				reportPath := filepath.Join(scanDir, "reports", "subdomains.md")
				if err := report.WriteSubdomainReport(result, reportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write subdomain report: %v\n", err)
				}

				rawPath := filepath.Join(scanDir, "raw", "subdomains.json")
				rawData, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling subdomains: %w", err)
				}
				return os.WriteFile(rawPath, rawData, 0644)
			},
		}

		portscanStage := pipeline.Stage{
			Name: "portscan",
			Run: func(ctx context.Context, scanDir string) error {
				subdomainsPath := filepath.Join(scanDir, "raw", "subdomains.json")
				subData, err := os.ReadFile(subdomainsPath)
				if err != nil {
					return fmt.Errorf("reading subdomains.json (run discover first): %w", err)
				}

				var discoveryResult discovery.DiscoveryResult
				if err := json.Unmarshal(subData, &discoveryResult); err != nil {
					return fmt.Errorf("parsing subdomains.json: %w", err)
				}

				var resolved []models.Subdomain
				for _, sub := range discoveryResult.Subdomains {
					if sub.Resolved && len(sub.IPs) > 0 {
						resolved = append(resolved, sub)
					}
				}

				if len(resolved) == 0 {
					fmt.Println("    [!] No resolved subdomains with IPs — skipping port scan")
					// Write an empty result so subsequent stages have a valid file.
					empty := portscan.PortScanResult{Target: domain, Hosts: []models.Host{}}
					rawData, _ := json.MarshalIndent(empty, "", "  ")
					rawPath := filepath.Join(scanDir, "raw", "ports.json")
					return os.WriteFile(rawPath, rawData, 0644)
				}

				fmt.Printf("    [>] Scanning %d resolved subdomains\n", len(resolved))

				portScanCfg := portscan.PortScanConfig{
					CdncheckPath:    "",
					MasscanPath:     "",
					NmapPath:        "",
					MasscanRate:     cfg.RateLimits.MasscanRate,
					NmapMaxParallel: cfg.RateLimits.NmapMaxParallel,
					SkipCDNCheck:    !cdncheckAvailable,
				}

				result, err := portscan.RunPortScan(ctx, resolved, portScanCfg)
				if err != nil {
					return fmt.Errorf("port scan pipeline: %w", err)
				}

				fmt.Printf("    [>] CDN: %d filtered, scanned: %d, open ports: %d\n",
					result.CDNCount, result.ScannedCount, result.TotalPorts)

				reportPath := filepath.Join(scanDir, "reports", "ports.md")
				if err := report.WritePortReport(result, reportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write port report: %v\n", err)
				}

				rawPath := filepath.Join(scanDir, "raw", "ports.json")
				rawData, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling port scan result: %w", err)
				}
				return os.WriteFile(rawPath, rawData, 0644)
			},
		}

		probeStage := pipeline.Stage{
			Name: "probe",
			Run: func(ctx context.Context, scanDir string) error {
				portsPath := filepath.Join(scanDir, "raw", "ports.json")
				portsData, err := os.ReadFile(portsPath)
				if err != nil {
					return fmt.Errorf("reading ports.json (run portscan first): %w", err)
				}

				var portResult portscan.PortScanResult
				if err := json.Unmarshal(portsData, &portResult); err != nil {
					return fmt.Errorf("parsing ports.json: %w", err)
				}

				hosts := hostsWithOpenPorts(portResult.Hosts)
				if len(hosts) == 0 {
					fmt.Println("    [!] No hosts with open ports — skipping HTTP probe")
					empty := httpprobe.HTTPProbeResult{Target: domain, Probes: []models.HTTPProbe{}}
					rawData, _ := json.MarshalIndent(empty, "", "  ")
					rawPath := filepath.Join(scanDir, "raw", "http-probes.json")
					return os.WriteFile(rawPath, rawData, 0644)
				}

				fmt.Printf("    [>] Probing %d hosts\n", len(hosts))

				screenshotDir := filepath.Join(scanDir, "screenshots")
				skipScreenshots := !gowitnessAvailable
				if !skipScreenshots {
					if err := storage.EnsureDir(screenshotDir); err != nil {
						fmt.Printf("    [!] Warning: could not create screenshot dir: %v\n", err)
						skipScreenshots = true
					}
				}

				probeCfg := httpprobe.HTTPProbeConfig{
					HttpxPath:        "",
					GowitnessPath:    "",
					HttpxThreads:     cfg.RateLimits.HttpxThreads,
					GowitnessThreads: 6,
					ScreenshotDir:    screenshotDir,
					SkipScreenshots:  skipScreenshots,
				}

				probeResult, err := httpprobe.RunHTTPProbe(ctx, hosts, probeCfg)
				if err != nil {
					return fmt.Errorf("HTTP probe pipeline: %w", err)
				}
				if probeResult.Target == "" {
					probeResult.Target = domain
				}

				fmt.Printf("    [>] Live services: %d\n", probeResult.LiveCount)

				reportPath := filepath.Join(scanDir, "reports", "http-probes.md")
				if err := report.WriteHTTPProbeReport(probeResult, reportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write HTTP probe report: %v\n", err)
				}

				rawPath := filepath.Join(scanDir, "raw", "http-probes.json")
				rawData, err := json.MarshalIndent(probeResult, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling HTTP probe result: %w", err)
				}
				return os.WriteFile(rawPath, rawData, 0644)
			},
		}

		vulnscanStage := pipeline.Stage{
			Name: "vulnscan",
			Run: func(ctx context.Context, scanDir string) error {
				if !nucleiAvailable {
					fmt.Println("    [!] nuclei not found — skipping vulnerability scan")
					return nil
				}

				portsPath := filepath.Join(scanDir, "raw", "ports.json")
				portsData, err := os.ReadFile(portsPath)
				if err != nil {
					return fmt.Errorf("reading ports.json (run portscan first): %w", err)
				}
				var portResult portscan.PortScanResult
				if err := json.Unmarshal(portsData, &portResult); err != nil {
					return fmt.Errorf("parsing ports.json: %w", err)
				}

				probesPath := filepath.Join(scanDir, "raw", "http-probes.json")
				probesData, err := os.ReadFile(probesPath)
				if err != nil {
					return fmt.Errorf("reading http-probes.json (run probe first): %w", err)
				}
				var probeResult httpprobe.HTTPProbeResult
				if err := json.Unmarshal(probesData, &probeResult); err != nil {
					return fmt.Errorf("parsing http-probes.json: %w", err)
				}

				fmt.Printf("    [>] Scanning %d hosts, %d HTTP probes (severity: %s)\n",
					len(portResult.Hosts), len(probeResult.Probes), severity)

				vulnCfg := vulnscan.VulnScanConfig{
					NucleiPath: "",
					Severity:   severity,
					Threads:    cfg.RateLimits.NucleiThreads,
					RateLimit:  cfg.RateLimits.NucleiRateLimit,
				}

				result, err := vulnscan.RunVulnScan(ctx, portResult.Hosts, probeResult.Probes, vulnCfg)
				if err != nil {
					return fmt.Errorf("vulnerability scan pipeline: %w", err)
				}
				if result.Target == "" {
					result.Target = domain
				}

				fmt.Printf("    [>] Total findings: %d\n", result.TotalCount)

				reportPath := filepath.Join(scanDir, "reports", "vulns.md")
				if err := report.WriteVulnReport(result, reportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write vuln report: %v\n", err)
				}

				rawPath := filepath.Join(scanDir, "raw", "vulns.json")
				rawData, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling vuln result: %w", err)
				}
				if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
					return fmt.Errorf("writing vulns.json: %w", err)
				}

				jsonlPath := filepath.Join(scanDir, "raw", "nuclei-output.jsonl")
				if err := writeNucleiJSONL(result.Vulnerabilities, jsonlPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write nuclei JSONL: %v\n", err)
				}

				if !skipPDF && python3Available {
					pdfPath := filepath.Join(scanDir, "reports", "vulns.pdf")
					generateNucPDF(ctx, pythonBinary, jsonlPath, pdfPath, domain)
				}

				return nil
			},
		}

		diffStage := pipeline.Stage{
			Name: "diff",
			Run: func(ctx context.Context, scanDir string) error {
				currentSnap, err := diff.LoadSnapshot(scanDir)
				if err != nil {
					return fmt.Errorf("loading current snapshot: %w", err)
				}

				// Open a second store connection for the historical lookup so
				// the stage is self-contained and does not rely on the outer store.
				diffStore, err := storage.NewStore(cfg.DBPath)
				if err != nil {
					return fmt.Errorf("opening database for diff: %w", err)
				}
				defer diffStore.Close()

				prevDir, err := findPreviousScanDir(domain, scanDir)
				if err != nil {
					// Non-fatal — just skip if history lookup fails.
					fmt.Printf("    [!] Warning: could not find previous scan: %v\n", err)
					return nil
				}
				if prevDir == "" {
					fmt.Println("    [>] No previous scan found — skipping diff")
					return nil
				}

				fmt.Printf("    [>] Comparing against %s\n", prevDir)

				previousSnap, err := diff.LoadSnapshot(prevDir)
				if err != nil {
					return fmt.Errorf("loading previous snapshot: %w", err)
				}

				result := diff.ComputeDiff(currentSnap, previousSnap)

				diffReportPath := filepath.Join(scanDir, "reports", "diff.md")
				if err := report.WriteDiffReport(result, diffReportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write diff report: %v\n", err)
				}

				danglingReportPath := filepath.Join(scanDir, "reports", "dangling-dns.md")
				if err := report.WriteDanglingDNSReport(currentSnap.Subdomains, danglingReportPath); err != nil {
					fmt.Printf("    [!] Warning: failed to write dangling DNS report: %v\n", err)
				}

				rawPath := filepath.Join(scanDir, "raw", "diff.json")
				rawData, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("marshaling diff result: %w", err)
				}
				if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
					return fmt.Errorf("writing diff.json: %w", err)
				}

				fmt.Printf("    [>] Subdomains: +%d new, -%d removed | Ports: +%d new, -%d closed | Vulns: +%d new, -%d resolved\n",
					len(result.NewSubdomains), len(result.RemovedSubdomains),
					len(result.NewPorts), len(result.ClosedPorts),
					len(result.NewVulns), len(result.ResolvedVulns))

				return nil
			},
		}

		// ── 8. Assemble stage list in canonical order ──────────────────────────
		allStages := []pipeline.Stage{
			discoverStage,
			portscanStage,
			probeStage,
			vulnscanStage,
			diffStage,
		}

		// ── 9. Build PipelineConfig ────────────────────────────────────────────
		pipelineCfg := pipeline.PipelineConfig{
			Target:  domain,
			ScanDir: scanDir,
			Stages:  stageList,
			Skip:    skipList,
			Resume:  resume,
			Timeout: timeout,
			OnStageStart: func(name string, index, total int) {
				fmt.Printf("[*] Stage %d/%d: %s...\n", index+1, total, name)
			},
			OnStageDone: func(name string, index, total int, err error, elapsed time.Duration) {
				if err != nil {
					fmt.Printf("[!] Stage %d/%d: %s FAILED (%s)\n",
						index+1, total, name, elapsed.Round(time.Millisecond))
				} else {
					fmt.Printf("[+] Stage %d/%d: %s complete (%s)\n",
						index+1, total, name, elapsed.Round(time.Millisecond))
				}
			},
		}

		// ── 10. Run the pipeline ───────────────────────────────────────────────
		fmt.Printf("[*] Starting full pipeline scan for %s\n", domain)

		// Use a background context — the orchestrator applies its own timeout.
		result, err := pipeline.RunPipeline(context.Background(), pipelineCfg, allStages, store, cfg)
		if err != nil {
			return fmt.Errorf("pipeline failed: %w", err)
		}

		// ── 11. Webhook notification (non-fatal) ───────────────────────────────
		if webhookURL != "" {
			notifyCfg := pipeline.NotifyConfig{WebhookURL: webhookURL}
			if notifyErr := notifyCfg.SendCompletion(result); notifyErr != nil {
				fmt.Printf("[!] Warning: webhook notification failed: %v\n", notifyErr)
			} else {
				fmt.Printf("[+] Completion notification sent to %s\n", webhookURL)
			}
		}

		// ── 12. Print final summary ────────────────────────────────────────────
		fmt.Println()
		fmt.Printf("[+] Scan complete!\n")
		fmt.Printf("    Target:    %s\n", result.Target)
		fmt.Printf("    Scan ID:   %s\n", result.ScanID)
		fmt.Printf("    Scan dir:  %s\n", result.ScanDir)
		fmt.Printf("    Status:    %s\n", result.Status)
		fmt.Printf("    Elapsed:   %s\n", result.Elapsed.Round(time.Second))
		fmt.Printf("    Stages:    %s\n", strings.Join(result.StagesRun, " -> "))

		if len(result.StageErrors) > 0 {
			fmt.Println()
			fmt.Println("[!] Stage errors:")
			for stage, errMsg := range result.StageErrors {
				fmt.Printf("    %-12s %s\n", stage+":", errMsg)
			}
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().StringP("domain", "d", "", "Target domain to scan (required)")
	scanCmd.Flags().String("scan-dir", "", "Use an existing scan directory (auto-creates new one if empty)")
	scanCmd.Flags().String("stages", "", "Comma-separated stage names to run (e.g. discover,portscan)")
	scanCmd.Flags().String("skip", "", "Comma-separated stage names to skip")
	scanCmd.Flags().Bool("resume", false, "Resume from the last incomplete scan for this domain")
	scanCmd.Flags().String("preset", "", "Named preset: bug-bounty, quick-recon, internal-pentest")
	scanCmd.Flags().String("severity", "critical,high,medium", "Nuclei severity filter (comma-separated)")
	scanCmd.Flags().Duration("timeout", 2*time.Hour, "Total pipeline timeout")
	scanCmd.Flags().String("notify-webhook", "", "HTTP webhook URL to POST a completion summary to")
	scanCmd.Flags().String("scope-domains", "", "Comma-separated allowed domain patterns (e.g. example.com,*.example.com)")
	scanCmd.Flags().Bool("skip-pdf", false, "Skip PDF report generation")

	scanCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(scanCmd)
}

// ── Package-level helpers ──────────────────────────────────────────────────────

// splitCSV splits a comma-separated string into a trimmed, non-empty slice.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// toolCheckEntry carries the result of a single pre-flight tool check.
type toolCheckEntry struct {
	name       string
	found      bool
	required   bool
	installCmd string
}

// checkAllScanTools probes every tool the scan pipeline may need and returns a
// map keyed by tool name so callers can look up individual results.
func checkAllScanTools() map[string]toolCheckEntry {
	checks := []struct {
		name       string
		required   bool
		installCmd string
	}{
		{"subfinder", true, "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"dig", true, "apt install dnsutils (or brew install bind on macOS)"},
		{"masscan", true, "apt install masscan (or brew install masscan on macOS)"},
		{"nmap", true, "apt install nmap (or brew install nmap on macOS)"},
		{"httpx", true, "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"tlsx", false, "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
		{"cdncheck", false, "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"},
		{"gowitness", false, "go install github.com/sensepost/gowitness@latest"},
		{"nuclei", false, "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	}

	results := make(map[string]toolCheckEntry, len(checks))
	for _, c := range checks {
		r := tools.CheckTool(tools.ToolRequirement{
			Name:       c.name,
			Binary:     c.name,
			Required:   c.required,
			InstallCmd: c.installCmd,
		})
		results[c.name] = toolCheckEntry{
			name:       c.name,
			found:      r.Found,
			required:   c.required,
			installCmd: c.installCmd,
		}
	}
	return results
}

// printToolCheckSummary prints a compact pre-flight report to stdout.
func printToolCheckSummary(results map[string]toolCheckEntry) {
	order := []string{"subfinder", "dig", "masscan", "nmap", "httpx", "tlsx", "cdncheck", "gowitness", "nuclei"}
	fmt.Println("[*] Pre-flight tool check:")
	for _, name := range order {
		r := results[name]
		status := "ok"
		if !r.found {
			if r.required {
				status = "MISSING (required)"
			} else {
				status = "not found (optional)"
			}
		}
		fmt.Printf("    %-12s %s\n", name+":", status)
	}
}
