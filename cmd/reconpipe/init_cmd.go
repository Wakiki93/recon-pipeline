package main

import (
	"fmt"
	"os"

	"github.com/hakim/reconpipe/internal/config"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/spf13/cobra"
)

var (
	initForce bool
	initDir   string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize reconpipe with default configuration",
	Long: `Creates a default configuration file (reconpipe.yaml), initializes the
scan directory structure, and sets up the database for storing scan metadata.

This is typically the first command you run when setting up reconpipe.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := "reconpipe.yaml"
		if initDir != "." {
			configPath = fmt.Sprintf("%s/reconpipe.yaml", initDir)
		}

		// Check if config already exists
		if _, err := os.Stat(configPath); err == nil && !initForce {
			return fmt.Errorf("config file already exists at %s. Use --force to overwrite", configPath)
		}

		// Create default config
		if err := config.WriteDefault(configPath); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
		fmt.Printf("Created %s with default configuration\n", configPath)

		// Load the config we just created to get paths
		cfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Create scan directory
		if err := storage.EnsureDir(cfg.ScanDir); err != nil {
			return fmt.Errorf("failed to create scan directory: %w", err)
		}
		fmt.Printf("Created scan directory: %s\n", cfg.ScanDir)

		// Initialize database
		store, err := storage.NewStore(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer store.Close()
		fmt.Printf("Initialized database: %s\n", cfg.DBPath)

		// Print success message
		fmt.Println()
		fmt.Println("ReconPipe initialized successfully!")
		fmt.Println("Run 'reconpipe check' to verify your tools.")

		return nil
	},
}

func init() {
	initCmd.Flags().BoolVar(&initForce, "force", false, "overwrite existing config file")
	initCmd.Flags().StringVar(&initDir, "dir", ".", "output directory")
	rootCmd.AddCommand(initCmd)
}
