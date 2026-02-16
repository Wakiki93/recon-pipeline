package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/hakim/reconpipe/internal/tools"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for required external tools",
	Long: `Verify that all external reconnaissance tools are installed and available.
Shows installation status, version information, and provides installation
instructions for missing tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get tool list
		toolList := tools.DefaultTools()

		// Check all tools
		results := tools.CheckTools(toolList)

		// Create table writer
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Tool\tStatus\tVersion\tPurpose")
		fmt.Fprintln(w, "----\t------\t-------\t-------")

		foundCount := 0
		requiredMissing := 0

		for _, result := range results {
			status := "[-]"
			version := "-"

			if result.Found {
				status = "[+]"
				foundCount++
				if result.Version != "" && result.Version != "unknown" {
					version = result.Version
				}
			} else if result.Tool.Required {
				requiredMissing++
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				result.Tool.Name,
				status,
				version,
				result.Tool.Purpose)
		}

		w.Flush()

		// Print installation instructions for missing tools
		fmt.Println()
		missingTools := false
		for _, result := range results {
			if !result.Found {
				if !missingTools {
					fmt.Println("Missing tools:")
					missingTools = true
				}
				required := ""
				if result.Tool.Required {
					required = " (REQUIRED)"
				}
				fmt.Printf("  %s%s\n    Install: %s\n",
					result.Tool.Name,
					required,
					result.Tool.InstallCmd)
			}
		}

		// Print summary
		fmt.Println()
		fmt.Printf("Summary: %d/%d tools found", foundCount, len(results))
		if requiredMissing > 0 {
			fmt.Printf(", %d required tools missing", requiredMissing)
		}
		fmt.Println()

		// Exit with error if required tools are missing
		if requiredMissing > 0 {
			return fmt.Errorf("required tools are missing")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
