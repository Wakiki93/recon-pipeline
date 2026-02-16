package main

import (
	"fmt"

	"github.com/hakim/reconpipe/internal/config"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "reconpipe",
	Short: "Subdomain-to-vulnerability reconnaissance pipeline",
	Long: `ReconPipe is a comprehensive reconnaissance tool that automates the process
of discovering subdomains, detecting dangling DNS records, scanning for open ports,
and identifying vulnerabilities.

It orchestrates external tools like subfinder, masscan, nmap, httpx, and nuclei
into a streamlined pipeline that generates structured reports and tracks changes
over time.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for commands that don't need it
		skipConfig := map[string]bool{
			"check":   true,
			"init":    true,
			"help":    true,
			"version": true,
		}

		if skipConfig[cmd.Name()] {
			return nil
		}

		// Load config if file exists
		if cfgFile != "" {
			var err error
			cfg, err = config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
		}

		return nil
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "reconpipe.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")

	// Version flag
	rootCmd.Version = "0.1.0-dev"
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}
