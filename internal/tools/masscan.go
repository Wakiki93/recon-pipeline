package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// MasscanPort represents a single discovered port
type MasscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// MasscanResult represents the scan results for a single IP
type MasscanResult struct {
	IP    string        `json:"ip"`
	Ports []MasscanPort `json:"ports"`
}

// RunMasscan executes masscan for the given IPs and returns parsed results.
// It writes IPs to a temp file and parses JSON output.
// If rate <= 0, defaults to 1000 packets/second.
func RunMasscan(ctx context.Context, ips []string, rate int, binaryPath string) ([]MasscanResult, error) {
	// Return early if no IPs provided
	if len(ips) == 0 {
		return []MasscanResult{}, nil
	}

	// Use provided binary path or fall back to tool name
	binary := "masscan"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Default rate to 1000 if not specified
	if rate <= 0 {
		rate = 1000
	}

	// Create temp file for input IPs
	inputFile, err := os.CreateTemp("", "masscan-input-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create input temp file: %w", err)
	}
	defer os.Remove(inputFile.Name())

	// Write IPs to temp file
	for _, ip := range ips {
		if _, err := fmt.Fprintln(inputFile, ip); err != nil {
			inputFile.Close()
			return nil, fmt.Errorf("failed to write IP to temp file: %w", err)
		}
	}
	inputFile.Close()

	// Create temp file for JSON output
	outputFile, err := os.CreateTemp("", "masscan-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create output temp file: %w", err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	// Build arguments
	args := []string{
		"-iL", inputFile.Name(),
		"-p1-65535",
		fmt.Sprintf("--rate=%d", rate),
		"-oJ", outputFile.Name(),
		"--wait", "2",
	}

	// Execute via RunTool
	_, err = RunTool(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}

	// Read the JSON output file
	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		// File might not exist if no ports were found
		if os.IsNotExist(err) {
			return []MasscanResult{}, nil
		}
		return nil, fmt.Errorf("failed to read masscan output: %w", err)
	}

	// Handle empty results
	if len(data) == 0 {
		return []MasscanResult{}, nil
	}

	// Clean up masscan JSON output (has trailing comma issue)
	// Replace patterns like ",\n]" with "\n]"
	cleaned := strings.ReplaceAll(string(data), ",\n]", "\n]")
	cleaned = strings.ReplaceAll(cleaned, ", ]", " ]")

	// Parse JSON
	var results []MasscanResult
	if err := json.Unmarshal([]byte(cleaned), &results); err != nil {
		return nil, fmt.Errorf("failed to parse masscan JSON: %w", err)
	}

	return results, nil
}
