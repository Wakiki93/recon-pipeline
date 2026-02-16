package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// TlsxResult represents the JSON output structure from tlsx
type TlsxResult struct {
	SubjectCN string   `json:"subject_cn"`
	SubjectAN []string `json:"subject_an"`
	Host      string   `json:"host"`
	Port      string   `json:"port"`
}

// RunTlsx executes tlsx for the given domain and returns discovered subdomains.
// It extracts subdomains from certificate SAN (Subject Alternative Name) and CN (Common Name),
// filters out wildcards and out-of-scope entries, and returns deduplicated results.
func RunTlsx(ctx context.Context, domain string, binaryPath string) ([]string, error) {
	// Use provided binary path or fall back to tool name
	binary := "tlsx"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Build arguments: -san -cn -silent -json
	args := []string{
		"-san",    // Extract Subject Alternative Names
		"-cn",     // Extract Common Name
		"-silent", // Quiet output
		"-json",   // JSON output format
	}

	// Execute via RunTool with domain piped to stdin
	result, err := RunTool(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("tlsx execution failed: %w", err)
	}

	// Parse JSONL output and extract subdomains
	subdomains := make(map[string]bool) // Use map for deduplication
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var tlsxResult TlsxResult
		if err := json.Unmarshal(line, &tlsxResult); err != nil {
			// Log warning and continue
			fmt.Printf("Warning: failed to parse tlsx JSON line: %v\n", err)
			continue
		}

		// Extract SubjectCN
		if tlsxResult.SubjectCN != "" {
			if isValidSubdomain(tlsxResult.SubjectCN, domain) {
				subdomains[tlsxResult.SubjectCN] = true
			}
		}

		// Extract all SubjectAN entries
		for _, san := range tlsxResult.SubjectAN {
			if isValidSubdomain(san, domain) {
				subdomains[san] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read tlsx output: %w", err)
	}

	// Convert map to slice
	result_list := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		result_list = append(result_list, subdomain)
	}

	return result_list, nil
}

// isValidSubdomain checks if a subdomain entry is valid for the target domain.
// It filters out wildcards and entries that don't end with the target domain.
func isValidSubdomain(entry, targetDomain string) bool {
	// Skip wildcards
	if strings.HasPrefix(entry, "*") {
		return false
	}

	// Skip entries that don't end with the target domain (out-of-scope)
	if !strings.HasSuffix(entry, targetDomain) {
		return false
	}

	return true
}
