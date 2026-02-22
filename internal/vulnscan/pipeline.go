package vulnscan

import (
	"context"
	"fmt"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// VulnScanConfig contains configuration for the vulnerability scanning pipeline
type VulnScanConfig struct {
	NucleiPath string
	Severity   string // comma-separated: "critical,high,medium"
	Threads    int
	RateLimit  int
	SkipNuclei bool
}

// VulnScanResult contains the complete results of vulnerability scanning
type VulnScanResult struct {
	Target          string                 `json:"target"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	TotalCount      int                    `json:"total_count"`
	SeverityCounts  map[string]int         `json:"severity_counts"`
	RawJSONLPath    string                 `json:"raw_jsonl_path,omitempty"`
}

// RunVulnScan orchestrates the full vulnerability scanning pipeline.
// It runs nuclei against all HTTP probe URLs, subdomain names, and IP addresses,
// deduplicates findings, and returns structured results with severity counts.
func RunVulnScan(ctx context.Context, hosts []models.Host, probes []models.HTTPProbe, cfg VulnScanConfig) (*VulnScanResult, error) {
	result := &VulnScanResult{
		Vulnerabilities: []models.Vulnerability{},
		SeverityCounts:  make(map[string]int),
	}

	// Derive target from first host's subdomain
	if len(hosts) > 0 && len(hosts[0].Subdomains) > 0 {
		result.Target = hosts[0].Subdomains[0]
	}

	// Build deduplicated target list from all available sources
	seen := make(map[string]bool)
	var targets []string

	addTarget := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	// HTTP probe URLs (for web-specific nuclei templates)
	for _, probe := range probes {
		addTarget(probe.URL)
	}

	// Subdomain names from hosts (for non-HTTP nuclei templates)
	for _, host := range hosts {
		for _, sub := range host.Subdomains {
			addTarget(sub)
		}
	}

	// IP addresses from hosts
	for _, host := range hosts {
		addTarget(host.IP)
	}

	if len(targets) == 0 {
		return result, nil
	}

	fmt.Printf("[*] Running nuclei against %d targets...\n", len(targets))

	nucleiResults, err := tools.RunNuclei(ctx, targets, cfg.Severity, cfg.Threads, cfg.RateLimit, cfg.NucleiPath)
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	// Deduplicate vulnerabilities by (TemplateID + Host) key
	type dedupKey struct {
		templateID string
		host       string
	}
	seenVulns := make(map[dedupKey]bool)

	for _, nr := range nucleiResults {
		vuln := tools.NucleiResultToVulnerability(nr)

		key := dedupKey{
			templateID: vuln.TemplateID,
			host:       vuln.Host,
		}

		if seenVulns[key] {
			continue
		}
		seenVulns[key] = true

		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		result.SeverityCounts[string(vuln.Severity)]++
	}

	result.TotalCount = len(result.Vulnerabilities)

	fmt.Printf("[+] Vulnerability scan complete: %d findings\n", result.TotalCount)

	return result, nil
}
