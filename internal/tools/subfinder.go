package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// SubfinderResult represents a single subdomain discovery result from subfinder
type SubfinderResult struct {
	Host   string `json:"host"`
	Source string `json:"source"`
}

// RunSubfinder executes subfinder for the given domain and returns parsed results.
// It uses JSON output mode (-oJ) with source attribution (-cs).
// If threads > 0, it sets the thread count (-t flag).
func RunSubfinder(ctx context.Context, domain string, threads int, binaryPath string) ([]SubfinderResult, error) {
	// Use provided binary path or fall back to tool name
	binary := "subfinder"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Build arguments: -d domain -silent -oJ -cs
	args := []string{
		"-d", domain,
		"-silent",
		"-oJ", // JSON output
		"-cs", // Include source attribution
	}

	// Add thread count if specified
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}

	// Execute via RunTool
	result, err := RunTool(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	// Parse JSONL output (one JSON object per line)
	var results []SubfinderResult
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var sfResult SubfinderResult
		if err := json.Unmarshal(line, &sfResult); err != nil {
			// Log warning and continue - some lines may not be valid JSON
			fmt.Printf("Warning: failed to parse subfinder JSON line: %v\n", err)
			continue
		}

		results = append(results, sfResult)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read subfinder output: %w", err)
	}

	return results, nil
}
