package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hakim/reconpipe/internal/httpprobe"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/portscan"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
	"github.com/spf13/cobra"
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Run HTTP probing and screenshots",
	Long: `Run HTTP probing via httpx and capture screenshots via gowitness.

This command reads port scan results from a prior scan, probes each host for
live HTTP/HTTPS services using httpx, and optionally captures screenshots of
all live services via gowitness.

Results are saved to:
  - {scan_dir}/reports/http-probes.md (report)
  - {scan_dir}/raw/http-probes.json   (raw data)

Scan metadata is updated in the configured database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Step 1: Get flags
		domain, _ := cmd.Flags().GetString("domain")
		scanDir, _ := cmd.Flags().GetString("scan-dir")
		skipScreenshots, _ := cmd.Flags().GetBool("skip-screenshots")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		// Step 2: Pre-flight check — verify required tools
		httpxTool := tools.ToolRequirement{
			Name:       "httpx",
			Binary:     "httpx",
			Required:   true,
			InstallCmd: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		}

		httpxResult := tools.CheckTool(httpxTool)
		if !httpxResult.Found {
			return fmt.Errorf("required tool 'httpx' not found. Install with: %s", httpxTool.InstallCmd)
		}

		// gowitness is optional — disable screenshots if not found
		gowinessTool := tools.ToolRequirement{
			Name:   "gowitness",
			Binary: "gowitness",
		}

		gowitnessResult := tools.CheckTool(gowinessTool)
		if !gowitnessResult.Found && !skipScreenshots {
			fmt.Println("[!] Warning: gowitness not found, screenshots will be skipped")
			skipScreenshots = true
		}

		// Step 3: Verify config was loaded
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 4: Determine scan directory
		if scanDir == "" {
			latestDir, err := findLatestScanDir(cfg.ScanDir, domain)
			if err != nil {
				return fmt.Errorf("finding latest scan directory: %w. Run 'reconpipe portscan -d %s' first", err, domain)
			}
			scanDir = latestDir
		}

		fmt.Printf("[*] Using scan directory: %s\n", scanDir)

		// Step 5: Read ports.json from prior portscan
		portsPath := filepath.Join(scanDir, "raw", "ports.json")
		portsData, err := os.ReadFile(portsPath)
		if err != nil {
			return fmt.Errorf("reading ports.json: %w. Run 'reconpipe portscan -d %s' first", err, domain)
		}

		var portResult portscan.PortScanResult
		if err := json.Unmarshal(portsData, &portResult); err != nil {
			return fmt.Errorf("parsing ports.json: %w", err)
		}

		// Step 6: Extract hosts that have open ports (skip CDN hosts with no ports)
		hosts := hostsWithOpenPorts(portResult.Hosts)
		if len(hosts) == 0 {
			fmt.Println("[!] No hosts with open ports found. Nothing to probe.")
			return nil
		}

		fmt.Printf("[*] Found %d hosts to probe\n", len(hosts))

		// Step 7: Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Step 8: Build HTTPProbeConfig
		screenshotDir := filepath.Join(scanDir, "screenshots")
		probeCfg := httpprobe.HTTPProbeConfig{
			HttpxPath:        "",
			GowitnessPath:    "",
			HttpxThreads:     cfg.RateLimits.HttpxThreads,
			GowitnessThreads: 6,
			ScreenshotDir:    screenshotDir,
			SkipScreenshots:  skipScreenshots,
		}

		// Step 9: Create screenshot directory
		if !skipScreenshots {
			if err := storage.EnsureDir(screenshotDir); err != nil {
				return fmt.Errorf("creating screenshot directory: %w", err)
			}
		}

		// Step 10: Run HTTP probe pipeline
		fmt.Printf("[*] Starting HTTP probe for %s\n", domain)
		probeResult, err := httpprobe.RunHTTPProbe(ctx, hosts, probeCfg)
		if err != nil {
			return fmt.Errorf("HTTP probe pipeline failed: %w", err)
		}

		// Ensure the target field is set to the requested domain
		if probeResult.Target == "" {
			probeResult.Target = domain
		}

		fmt.Printf("[+] HTTP probe complete: %d live services\n", probeResult.LiveCount)

		// Step 11: Write markdown report
		reportPath := filepath.Join(scanDir, "reports", "http-probes.md")
		if err := report.WriteHTTPProbeReport(probeResult, reportPath); err != nil {
			// Warn but do not fail — raw data is still saved below
			fmt.Printf("[!] Warning: failed to write report: %v\n", err)
		} else {
			fmt.Printf("[+] Report written to %s\n", reportPath)
		}

		// Step 12: Save raw JSON
		rawPath := filepath.Join(scanDir, "raw", "http-probes.json")
		rawData, err := json.MarshalIndent(probeResult, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling raw output: %w", err)
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			return fmt.Errorf("writing raw output: %w", err)
		}

		// Step 13: Update scan metadata in bbolt
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
			// Append "probe" to StagesRun if not already present
			alreadyRun := false
			for _, stage := range targetScan.StagesRun {
				if stage == "probe" {
					alreadyRun = true
					break
				}
			}
			if !alreadyRun {
				targetScan.StagesRun = append(targetScan.StagesRun, "probe")
			}

			if err := store.SaveScan(targetScan); err != nil {
				return fmt.Errorf("updating scan metadata: %w", err)
			}

			fmt.Printf("[+] Scan metadata updated (ID: %s)\n", targetScan.ID)
		} else {
			fmt.Println("[!] Warning: Could not find scan record to update in database")
		}

		// Step 14: Print final summary
		fmt.Println()
		fmt.Printf("[+] HTTP probe complete!\n")
		fmt.Printf("    Live services: %d\n", probeResult.LiveCount)
		fmt.Printf("    Report: %s\n", reportPath)
		if !skipScreenshots {
			fmt.Printf("    Screenshots: %s\n", screenshotDir)
		}

		return nil
	},
}

func init() {
	probeCmd.Flags().StringP("domain", "d", "", "Target domain")
	probeCmd.Flags().String("scan-dir", "", "Path to existing scan directory")
	probeCmd.Flags().Bool("skip-screenshots", false, "Skip gowitness screenshots")
	probeCmd.Flags().Duration("timeout", 30*time.Minute, "Overall timeout")
	probeCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(probeCmd)
}

// hostsWithOpenPorts returns all non-CDN hosts that have at least one open port,
// plus any CDN host that we still want to probe for HTTP services.
// The probe command is interested in all hosts — CDN or not — since HTTP
// services may run behind CDN endpoints too.
func hostsWithOpenPorts(hosts []models.Host) []models.Host {
	var result []models.Host
	for _, h := range hosts {
		if len(h.Ports) > 0 {
			result = append(result, h)
		}
	}
	return result
}
