package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

// DNSResult represents the DNS resolution result for a subdomain
type DNSResult struct {
	Subdomain string
	Resolved  bool
	IPs       []string
	CNAME     string
	Error     string
}

// ResolveSubdomains resolves DNS A/AAAA records for the given subdomains.
// It returns a slice of DNSResult containing resolution status and IPs.
func ResolveSubdomains(ctx context.Context, subdomains []string, binaryPath string) ([]DNSResult, error) {
	// Use provided binary path or fall back to tool name
	binary := "dig"
	if binaryPath != "" {
		binary = binaryPath
	}

	var results []DNSResult

	for _, subdomain := range subdomains {
		// Run dig +short for A/AAAA records
		args := []string{"+short", subdomain}

		result, err := RunTool(ctx, binary, args...)
		dnsResult := DNSResult{
			Subdomain: subdomain,
		}

		if err != nil {
			dnsResult.Error = err.Error()
			results = append(results, dnsResult)
			continue
		}

		// Parse output: lines containing . or : are IPs
		scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
		var ips []string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Check if line looks like an IP (contains . for IPv4 or : for IPv6)
			if strings.Contains(line, ".") || strings.Contains(line, ":") {
				// Simple heuristic: if it's not a FQDN with trailing dot, it's likely an IP
				if !strings.HasSuffix(line, ".") || (strings.Count(line, ".") <= 3 && !strings.Contains(line, ":")) {
					ips = append(ips, line)
				}
			}
		}

		if len(ips) > 0 {
			dnsResult.Resolved = true
			dnsResult.IPs = ips
		} else {
			dnsResult.Resolved = false
		}

		results = append(results, dnsResult)
	}

	return results, nil
}

// CheckCNAME checks if a subdomain has a CNAME record.
// Returns the CNAME target or empty string if no CNAME exists.
func CheckCNAME(ctx context.Context, subdomain string, binaryPath string) (string, error) {
	// Use provided binary path or fall back to tool name
	binary := "dig"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Run dig +short CNAME
	args := []string{"+short", "CNAME", subdomain}

	result, err := RunTool(ctx, binary, args...)
	if err != nil {
		return "", fmt.Errorf("CNAME check failed: %w", err)
	}

	// Parse output: first non-empty line is the CNAME target
	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			// Remove trailing dot if present
			return strings.TrimSuffix(line, "."), nil
		}
	}

	// No CNAME found
	return "", nil
}
