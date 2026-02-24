package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/pipeline"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/spf13/cobra"
)

var wizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Interactive wizard to configure and launch a scan",
	Long: `Walk through scan configuration one question at a time.

The wizard asks for a target domain, preset, severity, timeout, and optional
webhook URL.  It then prints a summary and asks for confirmation before
launching the full recon pipeline with the same logic as 'reconpipe scan'.`,
	RunE: runWizard,
}

func init() {
	rootCmd.AddCommand(wizardCmd)
}

// runWizard is the cobra RunE handler for the wizard command.
func runWizard(cmd *cobra.Command, args []string) error {
	if cfg == nil {
		return fmt.Errorf("config not loaded. Run 'reconpipe init' first to create config")
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("[*] ReconPipe Interactive Wizard")
	fmt.Println("[*] Press Enter to accept the default shown in brackets.")
	fmt.Println()

	// ── 1. Target domain ──────────────────────────────────────────────────────
	var domain string
	for {
		domain = wizardPrompt(reader, "[?] Target domain (required): ", "")
		if domain != "" {
			break
		}
		fmt.Println("[!] Target domain is required — please enter a domain name.")
	}

	// ── 2. Preset ─────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("    Presets:")
	fmt.Println("      [1] quick-recon      — fast surface mapping (discover + portscan)")
	fmt.Println("      [2] bug-bounty        — full pipeline, critical/high/medium findings")
	fmt.Println("      [3] internal-pentest  — full pipeline, all severity levels")
	fmt.Println("      [4] custom            — choose stages manually")

	presetChoice := wizardPrompt(reader, "[?] Choose preset [1]: ", "1")

	var presetName string
	var stageList []string

	switch presetChoice {
	case "1", "":
		presetName = "quick-recon"
	case "2":
		presetName = "bug-bounty"
	case "3":
		presetName = "internal-pentest"
	case "4":
		presetName = "custom"
	default:
		// If they typed the preset name directly, accept it.
		switch presetChoice {
		case "quick-recon", "bug-bounty", "internal-pentest":
			presetName = presetChoice
		default:
			fmt.Printf("[!] Unknown choice %q — defaulting to quick-recon\n", presetChoice)
			presetName = "quick-recon"
		}
	}

	// Resolve the preset from the registry (or build custom stage list).
	var resolvedPreset *pipeline.Preset
	if presetName == "custom" {
		defaultStages := "discover,portscan,probe,vulnscan,diff"
		stagesInput := wizardPrompt(
			reader,
			fmt.Sprintf("[?] Stages to run [%s]: ", defaultStages),
			defaultStages,
		)
		stageList = splitCSV(stagesInput)
		// Create a synthetic preset so severity logic below works correctly.
		resolvedPreset = &pipeline.Preset{
			Name:        "custom",
			Description: "Custom stage selection",
			Stages:      stageList,
			Severity:    "critical,high,medium",
			SkipPDF:     false,
		}
	} else {
		var err error
		resolvedPreset, err = pipeline.GetPreset(presetName)
		if err != nil {
			return fmt.Errorf("wizard: resolving preset: %w", err)
		}
		stageList = resolvedPreset.Stages
	}

	// ── 3. Severity (only when vulnscan is in the stage list) ─────────────────
	severity := resolvedPreset.Severity

	includesVulnscan := false
	for _, s := range stageList {
		if s == "vulnscan" {
			includesVulnscan = true
			break
		}
	}

	if includesVulnscan {
		fmt.Println()
		fmt.Println("    Severity options: critical, high, medium, low, info")
		defaultSeverity := severity
		if defaultSeverity == "" {
			defaultSeverity = "critical,high,medium"
		}
		severityInput := wizardPrompt(
			reader,
			fmt.Sprintf("[?] Severity filter [%s]: ", defaultSeverity),
			defaultSeverity,
		)
		severity = severityInput
	}

	// ── 4. Timeout ────────────────────────────────────────────────────────────
	fmt.Println()
	timeoutInput := wizardPrompt(reader, "[?] Timeout (Go duration, e.g. 30m, 1h, 2h) [2h]: ", "2h")
	timeout, err := time.ParseDuration(timeoutInput)
	if err != nil {
		fmt.Printf("[!] Could not parse %q as a duration — using default 2h\n", timeoutInput)
		timeout = 2 * time.Hour
	}

	// ── 5. Webhook URL ────────────────────────────────────────────────────────
	fmt.Println()
	webhookURL := wizardPrompt(reader, "[?] Webhook URL (optional, press Enter to skip): ", "")

	// ── Summary + confirmation ─────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("[*] Ready to scan:")
	fmt.Printf("    Target:   %s\n", domain)
	fmt.Printf("    Preset:   %s\n", resolvedPreset.Name)
	if includesVulnscan {
		fmt.Printf("    Severity: %s\n", severity)
	}
	fmt.Printf("    Timeout:  %s\n", timeout)
	if webhookURL != "" {
		fmt.Printf("    Webhook:  %s\n", webhookURL)
	} else {
		fmt.Println("    Webhook:  (none)")
	}
	fmt.Println()

	confirm := wizardPrompt(reader, "Start scan? [Y/n]: ", "y")
	if strings.EqualFold(confirm, "n") {
		fmt.Println("Cancelled.")
		return nil
	}

	// ── Launch the pipeline ────────────────────────────────────────────────────
	fmt.Printf("[*] Starting scan for %s\n", domain)
	fmt.Printf("[*] Using preset: %s — %s\n", resolvedPreset.Name, resolvedPreset.Description)

	// Pre-flight tool checks (reuses helpers from scan.go).
	toolCheckResults := checkAllScanTools()
	printToolCheckSummary(toolCheckResults)

	for _, r := range toolCheckResults {
		if r.required && !r.found {
			return fmt.Errorf("required tool %q not found — install with: %s", r.name, r.installCmd)
		}
	}

	tlsxAvailable := toolCheckResults["tlsx"].found
	cdncheckAvailable := toolCheckResults["cdncheck"].found
	gowitnessAvailable := toolCheckResults["gowitness"].found
	nucleiAvailable := toolCheckResults["nuclei"].found

	skipPDF := resolvedPreset.SkipPDF
	python3Available, pythonBinary := false, ""
	if !skipPDF {
		python3Available, pythonBinary = detectPython()
		if !python3Available {
			fmt.Println("[!] Warning: python3/python not found — PDF generation will be skipped")
		}
	}

	// Open bbolt store.
	store, err := storage.NewStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	// Build stage closures — delegate to the shared builder so we never
	// duplicate the per-stage closure code from scan.go.
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

	pipelineCfg := pipeline.PipelineConfig{
		Target:  domain,
		ScanDir: "",
		Stages:  stageList,
		Skip:    nil,
		Resume:  false,
		Timeout: timeout,
		OnStageStart: func(name string, index, total int) {
			fmt.Printf("[*] Stage %d/%d: %s...\n", index+1, total, name)
		},
		OnStageDone: func(name string, index, total int, stageErr error, elapsed time.Duration) {
			if stageErr != nil {
				fmt.Printf("[!] Stage %d/%d: %s FAILED (%s)\n",
					index+1, total, name, elapsed.Round(time.Millisecond))
			} else {
				fmt.Printf("[+] Stage %d/%d: %s complete (%s)\n",
					index+1, total, name, elapsed.Round(time.Millisecond))
			}
		},
	}

	result, err := pipeline.RunPipeline(context.Background(), pipelineCfg, allStages, store, cfg)
	if err != nil {
		return fmt.Errorf("pipeline failed: %w", err)
	}

	// Webhook notification (non-fatal).
	if webhookURL != "" {
		notifyCfg := pipeline.NotifyConfig{WebhookURL: webhookURL}
		if notifyErr := notifyCfg.SendCompletion(result); notifyErr != nil {
			fmt.Printf("[!] Warning: webhook notification failed: %v\n", notifyErr)
		} else {
			fmt.Printf("[+] Completion notification sent to %s\n", webhookURL)
		}
	}

	// Final summary.
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
}

// wizardPrompt prints a prompt, reads a line, trims whitespace, and returns
// the default value if the user pressed Enter without typing anything.
func wizardPrompt(reader *bufio.Reader, prompt, defaultVal string) string {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		// On EOF or read error, fall back to the default.
		return defaultVal
	}
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}
