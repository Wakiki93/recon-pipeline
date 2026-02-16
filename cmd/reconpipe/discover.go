package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hakim/reconpipe/internal/discovery"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/tools"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover subdomains for a target domain",
	Long: `Run the subdomain discovery pipeline for a target domain.

This command executes subfinder and tlsx (optional) to enumerate subdomains,
normalizes and deduplicates results, resolves DNS records, and classifies
dangling DNS entries for potential subdomain takeover.

Results are saved to:
  - {scan_dir}/{target}_{timestamp}/reports/subdomains.md (report)
  - {scan_dir}/{target}_{timestamp}/raw/subdomains.json (raw data)

Scan metadata is persisted to the configured database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flags
		domain, _ := cmd.Flags().GetString("domain")
		skipTlsx, _ := cmd.Flags().GetBool("skip-tlsx")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		// Step 1: Pre-flight check - verify required tools
		requiredTools := []tools.ToolRequirement{
			{Name: "subfinder", Binary: "subfinder", Required: true, InstallCmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
			{Name: "dig", Binary: "dig", Required: true, InstallCmd: "apt install dnsutils (or brew install bind on macOS)"},
		}

		tlsxTool := tools.ToolRequirement{Name: "tlsx", Binary: "tlsx", Required: false}
		tlsxAvailable := false

		for _, tool := range requiredTools {
			result := tools.CheckTool(tool)
			if !result.Found {
				return fmt.Errorf("required tool '%s' not found. Install with: %s", tool.Name, tool.InstallCmd)
			}
		}

		// Check tlsx availability
		tlsxResult := tools.CheckTool(tlsxTool)
		if tlsxResult.Found {
			tlsxAvailable = true
		} else if !skipTlsx {
			fmt.Println("[!] Warning: tlsx not found, skipping TLS certificate discovery")
			skipTlsx = true
		}

		// Step 2: Config loading - verify config was loaded
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 3: Create scan metadata
		scan := models.NewScan(domain)

		// Step 4: Create scan directory
		scanDir, err := storage.CreateScanDir(cfg.ScanDir, domain, scan.StartedAt)
		if err != nil {
			return fmt.Errorf("creating scan directory: %w", err)
		}
		scan.ScanDir = scanDir

		// Step 5: Open database
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer store.Close()

		// Step 6: Save scan metadata with StatusRunning
		scan.Status = models.StatusRunning
		if err := store.SaveScan(&scan.ScanMeta); err != nil {
			return fmt.Errorf("saving scan metadata: %w", err)
		}

		// Step 7: Print progress
		fmt.Printf("[*] Starting subdomain discovery for %s\n", domain)
		fmt.Printf("[*] Scan directory: %s\n", scanDir)

		// Step 8: Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Step 9: Build DiscoveryConfig
		discoveryCfg := discovery.DiscoveryConfig{
			SubfinderThreads: cfg.RateLimits.SubfinderThreads,
			SubfinderPath:    "", // Use binary from PATH
			TlsxPath:         "", // Use binary from PATH
			DigPath:          "", // Use binary from PATH
			SkipTlsx:         skipTlsx || !tlsxAvailable,
		}

		// Step 10: Run discovery
		result, err := discovery.RunDiscovery(ctx, domain, discoveryCfg)
		if err != nil {
			// Update status to failed before returning
			_ = store.UpdateScanStatus(scan.ID, models.StatusFailed)
			return fmt.Errorf("discovery pipeline failed: %w", err)
		}

		// Step 11: Print progress summary
		fmt.Printf("[+] Found %d unique subdomains (%d resolved, %d dangling)\n",
			result.UniqueCount, result.ResolvedCount, result.DanglingCount)

		// Step 12: Write markdown report
		reportPath := filepath.Join(scanDir, "reports", "subdomains.md")
		if err := report.WriteSubdomainReport(result, reportPath); err != nil {
			// Warn but don't fail - raw data is still saved
			fmt.Printf("[!] Warning: failed to write report: %v\n", err)
		} else {
			fmt.Printf("[+] Report written to %s\n", reportPath)
		}

		// Step 13: Save raw output as JSON
		rawPath := filepath.Join(scanDir, "raw", "subdomains.json")
		rawData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling raw output: %w", err)
		}
		if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
			return fmt.Errorf("writing raw output: %w", err)
		}

		// Step 14: Update scan metadata
		scan.Subdomains = result.Subdomains
		scan.StagesRun = append(scan.StagesRun, "discover")
		if err := store.SaveScan(&scan.ScanMeta); err != nil {
			return fmt.Errorf("updating scan metadata: %w", err)
		}

		// Step 15: Update status to complete
		if err := store.UpdateScanStatus(scan.ID, models.StatusComplete); err != nil {
			return fmt.Errorf("updating scan status: %w", err)
		}

		// Step 16: Print final summary
		fmt.Println()
		fmt.Printf("[+] Discovery complete!\n")
		fmt.Printf("    Scan ID: %s\n", scan.ID)
		fmt.Printf("    Total: %d | Unique: %d | Resolved: %d | Dangling: %d\n",
			result.TotalFound, result.UniqueCount, result.ResolvedCount, result.DanglingCount)
		fmt.Printf("    Report: %s\n", reportPath)

		return nil
	},
}

func init() {
	// Add flags
	discoverCmd.Flags().StringP("domain", "d", "", "Target domain to discover subdomains for (required)")
	discoverCmd.Flags().Bool("skip-tlsx", false, "Skip tlsx certificate discovery")
	discoverCmd.Flags().Duration("timeout", 10*time.Minute, "Overall discovery timeout")

	// Mark domain as required
	discoverCmd.MarkFlagRequired("domain")

	// Add to root command
	rootCmd.AddCommand(discoverCmd)
}
