package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/hakim/reconpipe/internal/httpprobe"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/portscan"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
	"github.com/hakim/reconpipe/internal/vulnscan"
	"github.com/spf13/cobra"
)

var vulnscanCmd = &cobra.Command{
	Use:   "vulnscan",
	Short: "Run vulnerability scanning via nuclei",
	Long: `Run nuclei vulnerability scanning against discovered hosts and HTTP endpoints.

This command reads HTTP probe results and port scan data from a prior scan, then
runs nuclei against all live HTTP services and discovered hosts to identify
vulnerabilities.

Results are saved to:
  - {scan_dir}/reports/vulns.md        (markdown report)
  - {scan_dir}/raw/vulns.json          (structured JSON)
  - {scan_dir}/raw/nuclei-output.jsonl (raw nuclei JSONL for tooling)
  - {scan_dir}/reports/vulns.pdf       (PDF report, if python3 available)

Scan metadata is updated in the configured database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Step 1: Get flags
		domain, _ := cmd.Flags().GetString("domain")
		scanDir, _ := cmd.Flags().GetString("scan-dir")
		severity, _ := cmd.Flags().GetString("severity")
		skipPDF, _ := cmd.Flags().GetBool("skip-pdf")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		// Step 2: Pre-flight checks
		// nuclei is required — hard error if missing
		nucleiTool := tools.ToolRequirement{
			Name:       "nuclei",
			Binary:     "nuclei",
			Required:   true,
			InstallCmd: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		}
		nucleiResult := tools.CheckTool(nucleiTool)
		if !nucleiResult.Found {
			return fmt.Errorf("required tool 'nuclei' not found. Install with: %s", nucleiTool.InstallCmd)
		}

		// python3 is optional — only needed for PDF generation
		python3Available := false
		pythonBinary := ""
		if !skipPDF {
			python3Available, pythonBinary = detectPython()
			if !python3Available {
				fmt.Println("[!] Warning: python3/python not found, PDF report generation will be skipped")
			}
		}

		// Step 3: Verify config was loaded
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 4: Determine scan directory
		if scanDir == "" {
			latestDir, err := findLatestScanDir(cfg.ScanDir, domain)
			if err != nil {
				return fmt.Errorf("finding latest scan directory: %w. Run 'reconpipe probe -d %s' first", err, domain)
			}
			scanDir = latestDir
		}

		fmt.Printf("[*] Using scan directory: %s\n", scanDir)

		// Step 5: Read http-probes.json from prior probe scan
		probesPath := filepath.Join(scanDir, "raw", "http-probes.json")
		probesData, err := os.ReadFile(probesPath)
		if err != nil {
			return fmt.Errorf("reading http-probes.json: %w. Run 'reconpipe probe -d %s' first", err, domain)
		}

		var probeResult httpprobe.HTTPProbeResult
		if err := json.Unmarshal(probesData, &probeResult); err != nil {
			return fmt.Errorf("parsing http-probes.json: %w", err)
		}

		// Step 6: Read ports.json for host data
		portsPath := filepath.Join(scanDir, "raw", "ports.json")
		portsData, err := os.ReadFile(portsPath)
		if err != nil {
			return fmt.Errorf("reading ports.json: %w. Run 'reconpipe portscan -d %s' first", err, domain)
		}

		var portResult portscan.PortScanResult
		if err := json.Unmarshal(portsData, &portResult); err != nil {
			return fmt.Errorf("parsing ports.json: %w", err)
		}

		fmt.Printf("[*] Loaded %d hosts and %d HTTP probes\n", len(portResult.Hosts), len(probeResult.Probes))

		// Step 7: Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Step 8: Build VulnScanConfig
		vulnCfg := vulnscan.VulnScanConfig{
			NucleiPath: "", // resolve from PATH
			Severity:   severity,
			Threads:    cfg.RateLimits.NucleiThreads,
			RateLimit:  cfg.RateLimits.NucleiRateLimit,
		}

		fmt.Printf("[*] Starting vulnerability scan for %s (severity: %s)\n", domain, severity)

		// Step 9: Run vulnerability scan
		result, err := vulnscan.RunVulnScan(ctx, portResult.Hosts, probeResult.Probes, vulnCfg)
		if err != nil {
			return fmt.Errorf("vulnerability scan pipeline failed: %w", err)
		}

		// Ensure target is set to the requested domain
		if result.Target == "" {
			result.Target = domain
		}

		// Step 10: Write markdown report
		reportPath := filepath.Join(scanDir, "reports", "vulns.md")
		if err := report.WriteVulnReport(result, reportPath); err != nil {
			// Warn but do not fail — raw data is still saved below
			fmt.Printf("[!] Warning: failed to write markdown report: %v\n", err)
		} else {
			fmt.Printf("[+] Report written to %s\n", reportPath)
		}

		// Step 11: Save structured JSON
		rawPath := filepath.Join(scanDir, "raw", "vulns.json")
		rawData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling raw output: %w", err)
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			return fmt.Errorf("writing raw output: %w", err)
		}

		// Step 12: Save nuclei-compatible JSONL for downstream tooling (e.g. Nuc-pdf)
		jsonlPath := filepath.Join(scanDir, "raw", "nuclei-output.jsonl")
		if err := writeNucleiJSONL(result.Vulnerabilities, jsonlPath); err != nil {
			// Non-fatal — PDF generation will fail gracefully if file is missing
			fmt.Printf("[!] Warning: failed to write nuclei JSONL: %v\n", err)
		}

		// Step 13: Generate PDF report via Nuc-pdf Python tool
		if !skipPDF && python3Available {
			pdfPath := filepath.Join(scanDir, "reports", "vulns.pdf")
			generateNucPDF(ctx, pythonBinary, jsonlPath, pdfPath, domain)
		}

		// Step 14: Update scan metadata in bbolt
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer store.Close()

		scans, err := store.ListScans(domain)
		if err != nil {
			return fmt.Errorf("listing scans: %w", err)
		}

		var targetScan *models.ScanMeta
		for _, scan := range scans {
			if scan.ScanDir == scanDir {
				targetScan = scan
				break
			}
		}

		if targetScan != nil {
			// Append "vulnscan" to StagesRun if not already present
			alreadyRun := false
			for _, stage := range targetScan.StagesRun {
				if stage == "vulnscan" {
					alreadyRun = true
					break
				}
			}
			if !alreadyRun {
				targetScan.StagesRun = append(targetScan.StagesRun, "vulnscan")
			}

			if err := store.SaveScan(targetScan); err != nil {
				return fmt.Errorf("updating scan metadata: %w", err)
			}

			fmt.Printf("[+] Scan metadata updated (ID: %s)\n", targetScan.ID)
		} else {
			fmt.Println("[!] Warning: Could not find scan record to update in database")
		}

		// Step 15: Print final summary with per-severity counts
		fmt.Println()
		fmt.Printf("[+] Vulnerability scan complete!\n")
		fmt.Printf("    Total findings: %d\n", result.TotalCount)
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				fmt.Printf("    %-10s %d\n", sev+":", count)
			}
		}
		fmt.Printf("    Report: %s\n", reportPath)
		fmt.Printf("    Raw JSON: %s\n", rawPath)

		return nil
	},
}

func init() {
	vulnscanCmd.Flags().StringP("domain", "d", "", "Target domain")
	vulnscanCmd.Flags().String("scan-dir", "", "Path to existing scan directory (auto-detects latest if empty)")
	vulnscanCmd.Flags().String("severity", "critical,high,medium", "Nuclei severity filter (comma-separated)")
	vulnscanCmd.Flags().Bool("skip-pdf", false, "Skip PDF report generation")
	vulnscanCmd.Flags().Duration("timeout", 60*time.Minute, "Overall timeout")
	vulnscanCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(vulnscanCmd)
}

// nucleiJSONLRecord mirrors nuclei's JSONL output format.
// Field names use hyphens to match what Nuc-pdf and other nuclei tooling expect.
type nucleiJSONLRecord struct {
	TemplateID    string            `json:"template-id"`
	Info          nucleiJSONLInfo   `json:"info"`
	Host          string            `json:"host"`
	MatchedAt     string            `json:"matched-at"`
	Timestamp     string            `json:"timestamp"`
	MatcherStatus bool              `json:"matcher-status"`
}

type nucleiJSONLInfo struct {
	Name           string                  `json:"name"`
	Severity       string                  `json:"severity"`
	Description    string                  `json:"description,omitempty"`
	Classification *nucleiJSONLClassify    `json:"classification,omitempty"`
	Remediation    string                  `json:"remediation,omitempty"`
}

type nucleiJSONLClassify struct {
	CVSSScore float64 `json:"cvss-score,omitempty"`
}

// writeNucleiJSONL serialises vulnerabilities as nuclei-compatible JSONL so
// downstream tools (e.g. Nuc-pdf) can parse the file without modification.
// One JSON object is written per line; no trailing comma or array wrapper.
func writeNucleiJSONL(vulns []models.Vulnerability, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating JSONL file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for _, v := range vulns {
		matchedAt := v.MatchedAt
		if matchedAt == "" {
			matchedAt = v.URL
		}
		if matchedAt == "" {
			matchedAt = v.Host
		}

		rec := nucleiJSONLRecord{
			TemplateID: v.TemplateID,
			Info: nucleiJSONLInfo{
				Name:        v.Name,
				Severity:    string(v.Severity),
				Description: v.Description,
			},
			Host:          v.Host,
			MatchedAt:     matchedAt,
			Timestamp:     now,
			MatcherStatus: true,
		}

		line, err := json.Marshal(rec)
		if err != nil {
			// Skip malformed records rather than aborting the whole file
			fmt.Printf("[!] Warning: skipping vulnerability %q in JSONL: %v\n", v.TemplateID, err)
			continue
		}

		if _, err := w.Write(line); err != nil {
			return fmt.Errorf("writing JSONL record: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing JSONL newline: %w", err)
		}
	}

	return w.Flush()
}

// detectPython checks for python3 first (preferred), then python as a fallback.
// Returns (available bool, binaryName string).
func detectPython() (bool, string) {
	for _, binary := range []string{"python3", "python"} {
		checkResult := tools.CheckTool(tools.ToolRequirement{
			Name:   binary,
			Binary: binary,
		})
		if checkResult.Found {
			return true, binary
		}
	}
	return false, ""
}

// generateNucPDF calls the Nuc-pdf Python tool to produce a polished PDF report.
// Failures are treated as warnings — the pipeline continues without a PDF.
func generateNucPDF(ctx context.Context, pythonBinary, jsonlPath, pdfPath, domain string) {
	pdfCmd := exec.CommandContext(ctx, pythonBinary, "-m", "nucleireport", "generate",
		"-i", jsonlPath,
		"-o", pdfPath,
		"--title", fmt.Sprintf("%s Vulnerability Assessment", domain),
	)

	output, err := pdfCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] Warning: PDF report generation failed: %v\n%s\n", err, string(output))
		return
	}

	fmt.Printf("[+] PDF report written to %s\n", pdfPath)
}
