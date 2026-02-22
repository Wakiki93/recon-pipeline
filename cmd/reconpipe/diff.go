package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hakim/reconpipe/internal/diff"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare two scans and report what changed",
	Long: `Compare the current scan against a previous scan for a target domain.

This command loads structured JSON output from two scan directories, computes the
delta across subdomains, open ports, and vulnerabilities, and writes diff reports.

Results are saved to:
  - {scan_dir}/reports/diff.md        (markdown change report)
  - {scan_dir}/reports/dangling-dns.md (dangling DNS report for current scan)
  - {scan_dir}/raw/diff.json           (structured diff JSON)

When no --compare directory is supplied the second-most-recent scan for the domain
is located automatically via the scan database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Step 1: Get flags
		domain, _ := cmd.Flags().GetString("domain")
		scanDir, _ := cmd.Flags().GetString("scan-dir")
		compareDir, _ := cmd.Flags().GetString("compare")

		// Step 2: Config check
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 3: Resolve current scan directory
		if scanDir == "" {
			latestDir, err := findLatestScanDir(cfg.ScanDir, domain)
			if err != nil {
				return fmt.Errorf("finding latest scan directory: %w. Run 'reconpipe discover -d %s' first", err, domain)
			}
			scanDir = latestDir
		}

		fmt.Printf("[*] Current scan directory: %s\n", scanDir)

		// Step 4: Resolve previous scan directory
		if compareDir == "" {
			prevDir, err := findPreviousScanDir(domain, scanDir)
			if err != nil {
				return fmt.Errorf("looking up scan history: %w", err)
			}
			if prevDir == "" {
				fmt.Printf("[!] No previous scan found for comparison\n")
				return nil
			}
			compareDir = prevDir
		}

		fmt.Printf("[*] Previous scan directory: %s\n", compareDir)

		// Step 5: Load both snapshots
		currentSnap, err := diff.LoadSnapshot(scanDir)
		if err != nil {
			return fmt.Errorf("loading current snapshot: %w", err)
		}

		previousSnap, err := diff.LoadSnapshot(compareDir)
		if err != nil {
			return fmt.Errorf("loading previous snapshot: %w", err)
		}

		fmt.Printf("[*] Current:  %d subdomains, %d hosts, %d vulns\n",
			len(currentSnap.Subdomains), len(currentSnap.Hosts), len(currentSnap.Vulnerabilities))
		fmt.Printf("[*] Previous: %d subdomains, %d hosts, %d vulns\n",
			len(previousSnap.Subdomains), len(previousSnap.Hosts), len(previousSnap.Vulnerabilities))

		// Step 6: Compute diff
		result := diff.ComputeDiff(currentSnap, previousSnap)

		// Step 7: Write diff markdown report
		diffReportPath := filepath.Join(scanDir, "reports", "diff.md")
		if err := report.WriteDiffReport(result, diffReportPath); err != nil {
			// Warn but do not abort — raw JSON is still persisted below
			fmt.Printf("[!] Warning: failed to write diff report: %v\n", err)
		} else {
			fmt.Printf("[+] Diff report written to %s\n", diffReportPath)
		}

		// Step 8: Write dangling DNS report (current snapshot only)
		danglingReportPath := filepath.Join(scanDir, "reports", "dangling-dns.md")
		if err := report.WriteDanglingDNSReport(currentSnap.Subdomains, danglingReportPath); err != nil {
			fmt.Printf("[!] Warning: failed to write dangling DNS report: %v\n", err)
		} else {
			fmt.Printf("[+] Dangling DNS report written to %s\n", danglingReportPath)
		}

		// Step 9: Save diff result as JSON
		rawPath := filepath.Join(scanDir, "raw", "diff.json")
		rawData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling diff result: %w", err)
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			return fmt.Errorf("writing diff.json: %w", err)
		}
		fmt.Printf("[+] Diff JSON written to %s\n", rawPath)

		// Step 10: Update bbolt — append "diff" to StagesRun
		if err := appendDiffStage(domain, scanDir); err != nil {
			// Non-fatal: metadata update failure should not fail the command
			fmt.Printf("[!] Warning: failed to update scan metadata: %v\n", err)
		}

		// Step 11: Print summary
		fmt.Println()
		fmt.Printf("[+] Diff complete!\n")
		fmt.Printf("    Subdomains: +%d new, -%d removed\n",
			len(result.NewSubdomains), len(result.RemovedSubdomains))
		fmt.Printf("    Ports:      +%d new, -%d closed\n",
			len(result.NewPorts), len(result.ClosedPorts))
		fmt.Printf("    Vulns:      +%d new, -%d resolved\n",
			len(result.NewVulns), len(result.ResolvedVulns))
		if len(result.NewlyDangling) > 0 {
			fmt.Printf("    Dangling:   %d newly dangling (takeover risk!)\n", len(result.NewlyDangling))
		}

		return nil
	},
}

// findPreviousScanDir returns the ScanDir of the scan immediately preceding
// currentScanDir in the sorted history for domain. Returns ("", nil) when there
// is no prior scan — the caller interprets that as a graceful no-op.
func findPreviousScanDir(domain, currentScanDir string) (string, error) {
	store, err := storage.NewStore(cfg.DBPath)
	if err != nil {
		return "", fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	scans, err := store.ListScans(domain)
	if err != nil {
		return "", fmt.Errorf("listing scans: %w", err)
	}

	// scans is sorted newest-first. Walk until we find one whose ScanDir
	// differs from the current scan, then return that as the previous.
	for _, scan := range scans {
		if scan.ScanDir != currentScanDir {
			return scan.ScanDir, nil
		}
	}

	return "", nil
}

// appendDiffStage opens bbolt, finds the scan record for scanDir, and appends
// "diff" to its StagesRun list (idempotent).
func appendDiffStage(domain, scanDir string) error {
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

	if targetScan == nil {
		fmt.Println("[!] Warning: Could not find scan record to update in database")
		return nil
	}

	// Idempotent append
	for _, stage := range targetScan.StagesRun {
		if stage == "diff" {
			return nil
		}
	}
	targetScan.StagesRun = append(targetScan.StagesRun, "diff")

	if err := store.SaveScan(targetScan); err != nil {
		return fmt.Errorf("saving scan metadata: %w", err)
	}

	fmt.Printf("[+] Scan metadata updated (ID: %s)\n", targetScan.ID)
	return nil
}

func init() {
	diffCmd.Flags().StringP("domain", "d", "", "Target domain (required)")
	diffCmd.Flags().String("scan-dir", "", "Current scan directory (auto-detects latest if empty)")
	diffCmd.Flags().String("compare", "", "Previous scan directory to compare against (auto-detects second-latest if empty)")
	diffCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(diffCmd)
}
