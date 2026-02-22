package main

import (
	"fmt"
	"strings"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show scan history for a domain",
	Long: `Display a formatted table of past scans for a target domain.

Scans are listed newest-first. Each row shows the scan ID (truncated), start time,
completion status, and which pipeline stages were run.

Use --limit to cap the number of rows shown (default: 10).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Step 1: Get flags
		domain, _ := cmd.Flags().GetString("domain")
		limit, _ := cmd.Flags().GetInt("limit")

		// Step 2: Config check
		if cfg == nil {
			return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
		}

		// Step 3: Open bbolt store
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer store.Close()

		// Step 4: List scans (sorted newest-first by store.ListScans)
		scans, err := store.ListScans(domain)
		if err != nil {
			return fmt.Errorf("listing scans for %s: %w", domain, err)
		}

		if len(scans) == 0 {
			fmt.Printf("No scan history found for %s\n", domain)
			return nil
		}

		// Step 5: Apply limit
		if limit > 0 && len(scans) > limit {
			scans = scans[:limit]
		}

		// Step 6: Print formatted table
		const separator = "────────────────────────────────────────────────────────────────────────"

		fmt.Printf("\nScan History for %s\n", domain)
		fmt.Println(separator)
		fmt.Printf("  %-3s  %-12s  %-20s  %-10s  %s\n", "#", "Scan ID", "Started", "Status", "Stages")
		fmt.Println(separator)

		for i, scan := range scans {
			shortID := shortScanID(scan.ID)
			started := scan.StartedAt.UTC().Format("2006-01-02 15:04")
			status := formatStatus(scan.Status)
			stages := formatStages(scan.StagesRun)

			fmt.Printf("  %-3d  %-12s  %-20s  %-10s  %s\n",
				i+1, shortID, started, status, stages)
		}

		fmt.Println(separator)
		fmt.Printf("Total: %d scan(s)\n\n", len(scans))

		return nil
	},
}

// shortScanID returns the first 8 characters of a UUID followed by "..." for
// compact table display. Falls back to the full ID when shorter than 8 chars.
func shortScanID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "..."
}

// formatStatus converts a ScanStatus to a consistent lowercase display string.
func formatStatus(s models.ScanStatus) string {
	switch s {
	case models.StatusComplete:
		return "complete"
	case models.StatusFailed:
		return "failed"
	case models.StatusRunning:
		return "running"
	case models.StatusPending:
		return "pending"
	default:
		return string(s)
	}
}

// formatStages joins the StagesRun slice into a comma-separated string.
// Returns "-" when no stages are recorded.
func formatStages(stages []string) string {
	if len(stages) == 0 {
		return "-"
	}
	return strings.Join(stages, ", ")
}

func init() {
	historyCmd.Flags().StringP("domain", "d", "", "Target domain (required)")
	historyCmd.Flags().Int("limit", 10, "Maximum number of scans to display")
	historyCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(historyCmd)
}
