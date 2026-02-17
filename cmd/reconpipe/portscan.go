package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/discovery"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/portscan"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
	"github.com/spf13/cobra"
)

var portscanCmd = &cobra.Command{
	Use:   "portscan",
	Short: "Run CDN detection and port scanning",
	Long: `Run the port scanning pipeline for a target domain.

This command reads subdomain discovery results from a prior scan, filters CDN IPs
via cdncheck, discovers open ports via masscan, and fingerprints services via nmap.

Results are saved to:
  - {scan_dir}/reports/ports.md (report)
  - {scan_dir}/raw/ports.json (raw data)

Scan metadata is updated in the configured database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		domain, _ := cmd.Flags().GetString("domain")
		scanDir, _ := cmd.Flags().GetString("scan-dir")
		skipCDNCheck, _ := cmd.Flags().GetBool("skip-cdncheck")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		// Step 1: Pre-flight check - verify required tools
		requiredTools := []tools.ToolRequirement{
			{Name: "masscan", Binary: "masscan", Required: true, InstallCmd: "apt install masscan (or brew install masscan on macOS)"},
			{Name: "nmap", Binary: "nmap", Required: true, InstallCmd: "apt install nmap (or brew install nmap on macOS)"},
		}

		cdncheckTool := tools.ToolRequirement{Name: "cdncheck", Binary: "cdncheck", Required: false}
		cdncheckAvailable := false

		for _, tool := range requiredTools {
			result := tools.CheckTool(tool)
			if !result.Found {
				return fmt.Errorf("required tool '%s' not found. Install with: %s", tool.Name, tool.InstallCmd)
			}
		}

		// Check cdncheck availability
		cdncheckResult := tools.CheckTool(cdncheckTool)
		if cdncheckResult.Found {
			cdncheckAvailable = true
		} else if !skipCDNCheck {
			fmt.Println("[!] Warning: cdncheck not found, skipping CDN detection")
			skipCDNCheck = true
		}

		// Step 2: Config check - verify config was loaded
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 3: Determine scan directory
		if scanDir == "" {
			// Find latest scan dir for the domain
			latestDir, err := findLatestScanDir(cfg.ScanDir, domain)
			if err != nil {
				return fmt.Errorf("finding latest scan directory: %w. Run 'reconpipe discover -d %s' first", err, domain)
			}
			scanDir = latestDir
		}

		fmt.Printf("[*] Using scan directory: %s\n", scanDir)

		// Step 4: Read subdomains.json from prior discover scan
		subdomainsPath := filepath.Join(scanDir, "raw", "subdomains.json")
		subdomainsData, err := os.ReadFile(subdomainsPath)
		if err != nil {
			return fmt.Errorf("reading subdomains.json: %w. Run 'reconpipe discover' first", err)
		}

		var discoveryResult discovery.DiscoveryResult
		if err := json.Unmarshal(subdomainsData, &discoveryResult); err != nil {
			return fmt.Errorf("parsing subdomains.json: %w", err)
		}

		// Step 5: Filter to only resolved subdomains with IPs
		var resolvedSubdomains []models.Subdomain
		for _, sub := range discoveryResult.Subdomains {
			if sub.Resolved && len(sub.IPs) > 0 {
				resolvedSubdomains = append(resolvedSubdomains, sub)
			}
		}

		if len(resolvedSubdomains) == 0 {
			fmt.Println("[!] No resolved subdomains found with IPs. Nothing to scan.")
			return nil
		}

		fmt.Printf("[*] Found %d resolved subdomains to scan\n", len(resolvedSubdomains))

		// Step 6: Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Step 7: Build PortScanConfig
		portScanCfg := portscan.PortScanConfig{
			CdncheckPath:    "", // Use binary from PATH
			MasscanPath:     "", // Use binary from PATH
			NmapPath:        "", // Use binary from PATH
			MasscanRate:     cfg.RateLimits.MasscanRate,
			NmapMaxParallel: cfg.RateLimits.NmapMaxParallel,
			SkipCDNCheck:    skipCDNCheck || !cdncheckAvailable,
		}

		// Step 8: Print progress
		fmt.Printf("[*] Starting port scan for %s\n", domain)

		// Step 9: Run port scan
		result, err := portscan.RunPortScan(ctx, resolvedSubdomains, portScanCfg)
		if err != nil {
			return fmt.Errorf("port scan pipeline failed: %w", err)
		}

		// Step 10: Print progress summary
		fmt.Printf("[+] Port scan complete: %d CDN hosts, %d scanned, %d open ports\n",
			result.CDNCount, result.ScannedCount, result.TotalPorts)

		// Step 11: Write markdown report
		reportPath := filepath.Join(scanDir, "reports", "ports.md")
		if err := report.WritePortReport(result, reportPath); err != nil {
			// Warn but don't fail - raw data is still saved
			fmt.Printf("[!] Warning: failed to write report: %v\n", err)
		} else {
			fmt.Printf("[+] Report written to %s\n", reportPath)
		}

		// Step 12: Save raw output as JSON
		rawPath := filepath.Join(scanDir, "raw", "ports.json")
		rawData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling raw output: %w", err)
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			return fmt.Errorf("writing raw output: %w", err)
		}

		// Step 13: Open database and update scan
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer store.Close()

		// Find the scan record for this scan directory
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
			// Step 14: Update scan metadata
			// Build a full Scan object to update
			fullScan := &models.Scan{
				ScanMeta: *targetScan,
			}

			// Load existing subdomains if available
			fullScan.Subdomains = discoveryResult.Subdomains

			// Update hosts from port scan result
			fullScan.Hosts = result.Hosts

			// Append "portscan" to StagesRun if not already present
			alreadyRun := false
			for _, stage := range fullScan.StagesRun {
				if stage == "portscan" {
					alreadyRun = true
					break
				}
			}
			if !alreadyRun {
				fullScan.StagesRun = append(fullScan.StagesRun, "portscan")
			}

			// Save updated scan
			if err := store.SaveScan(&fullScan.ScanMeta); err != nil {
				return fmt.Errorf("updating scan metadata: %w", err)
			}

			fmt.Printf("[+] Scan metadata updated (ID: %s)\n", targetScan.ID)
		} else {
			fmt.Println("[!] Warning: Could not find scan record to update in database")
		}

		// Step 15: Print final summary
		fmt.Println()
		fmt.Printf("[+] Port scan complete!\n")
		fmt.Printf("    CDN filtered: %d hosts\n", result.CDNCount)
		fmt.Printf("    Hosts scanned: %d\n", result.ScannedCount)
		fmt.Printf("    Total ports found: %d\n", result.TotalPorts)
		fmt.Printf("    Report: %s\n", reportPath)

		return nil
	},
}

func init() {
	// Add flags
	portscanCmd.Flags().StringP("domain", "d", "", "Target domain to scan ports for (required)")
	portscanCmd.Flags().String("scan-dir", "", "Path to existing scan directory (auto-detects latest if empty)")
	portscanCmd.Flags().Bool("skip-cdncheck", false, "Skip CDN detection")
	portscanCmd.Flags().Duration("timeout", 30*time.Minute, "Overall timeout")

	// Mark domain as required
	portscanCmd.MarkFlagRequired("domain")

	// Add to root command
	rootCmd.AddCommand(portscanCmd)
}

// findLatestScanDir finds the most recent scan directory for a domain.
// It looks for directories matching {domain}_* pattern and returns the newest.
func findLatestScanDir(baseDir, domain string) (string, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "", fmt.Errorf("reading scan directory: %w", err)
	}

	// Sanitize domain to match directory naming convention
	sanitized := storage.SanitizeTarget(domain)
	prefix := sanitized + "_"

	// Collect matching directories
	var matchingDirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			matchingDirs = append(matchingDirs, entry.Name())
		}
	}

	if len(matchingDirs) == 0 {
		return "", fmt.Errorf("no scan directories found for domain %s", domain)
	}

	// Sort descending (newest first due to timestamp format)
	sort.Sort(sort.Reverse(sort.StringSlice(matchingDirs)))

	// Return full path of the latest directory
	return filepath.Join(baseDir, matchingDirs[0]), nil
}
