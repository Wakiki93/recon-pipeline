package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/pipeline"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
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
		// Stage closures are constructed by the shared helper in stages.go so
		// that wizard.go can reuse them without duplicating code.
		allStages := buildScanStages(
			domain,
			severity,
			skipPDF,
			python3Available,
			pythonBinary,
			tlsxAvailable,
			cdncheckAvailable,
			gowitnessAvailable,
			nucleiAvailable,
		)

		// ── 8. Build PipelineConfig ────────────────────────────────────────────
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

		// ── 9. Run the pipeline ────────────────────────────────────────────────
		fmt.Printf("[*] Starting full pipeline scan for %s\n", domain)

		// Use a background context — the orchestrator applies its own timeout.
		result, err := pipeline.RunPipeline(context.Background(), pipelineCfg, allStages, store, cfg)
		if err != nil {
			return fmt.Errorf("pipeline failed: %w", err)
		}

		// ── 10. Webhook notification (non-fatal) ───────────────────────────────
		if webhookURL != "" {
			notifyCfg := pipeline.NotifyConfig{WebhookURL: webhookURL}
			if notifyErr := notifyCfg.SendCompletion(result); notifyErr != nil {
				fmt.Printf("[!] Warning: webhook notification failed: %v\n", notifyErr)
			} else {
				fmt.Printf("[+] Completion notification sent to %s\n", webhookURL)
			}
		}

		// ── 11. Print final summary ────────────────────────────────────────────
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
