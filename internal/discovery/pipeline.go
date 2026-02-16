package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// DiscoveryResult contains the complete results of subdomain discovery
type DiscoveryResult struct {
	Target        string              `json:"target"`
	Subdomains    []models.Subdomain  `json:"subdomains"`
	TotalFound    int                 `json:"total_found"`
	UniqueCount   int                 `json:"unique_count"`
	ResolvedCount int                 `json:"resolved_count"`
	DanglingCount int                 `json:"dangling_count"`
	Sources       map[string]int      `json:"sources"`
}

// DiscoveryConfig contains configuration for the discovery pipeline
type DiscoveryConfig struct {
	SubfinderThreads int
	SubfinderPath    string
	TlsxPath         string
	DigPath          string
	SkipTlsx         bool
}

// RunDiscovery orchestrates the full subdomain discovery pipeline.
// It runs subfinder and tlsx (if enabled), normalizes and deduplicates results,
// resolves DNS, and classifies dangling entries.
func RunDiscovery(ctx context.Context, domain string, cfg DiscoveryConfig) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Target:  domain,
		Sources: make(map[string]int),
	}

	// Map for deduplication: key=normalized subdomain, value=source
	subdomainMap := make(map[string]string)

	// Step 1: Run subfinder
	fmt.Printf("Running subfinder for %s...\n", domain)
	subfinderResults, err := tools.RunSubfinder(ctx, domain, cfg.SubfinderThreads, cfg.SubfinderPath)
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	// Collect subfinder results
	for _, sf := range subfinderResults {
		normalized := normalizeSubdomain(sf.Host)
		if normalized == "" {
			continue
		}

		result.TotalFound++

		// First source wins for dedup
		if _, exists := subdomainMap[normalized]; !exists {
			subdomainMap[normalized] = sf.Source
		}
	}
	result.Sources["subfinder"] = len(subfinderResults)

	// Step 2: Run tlsx (if not skipped)
	if !cfg.SkipTlsx {
		fmt.Printf("Running tlsx for %s...\n", domain)
		tlsxResults, err := tools.RunTlsx(ctx, domain, cfg.TlsxPath)
		if err != nil {
			// Log warning but continue - tlsx is optional
			fmt.Printf("Warning: tlsx execution failed: %v\n", err)
		} else {
			// Collect tlsx results
			for _, subdomain := range tlsxResults {
				normalized := normalizeSubdomain(subdomain)
				if normalized == "" {
					continue
				}

				result.TotalFound++

				// First source wins for dedup
				if _, exists := subdomainMap[normalized]; !exists {
					subdomainMap[normalized] = "tlsx"
				}
			}
			result.Sources["tlsx"] = len(tlsxResults)
		}
	}

	// Step 3: Build Subdomain slice from deduplicated map
	subdomains := make([]models.Subdomain, 0, len(subdomainMap))
	for subdomain, source := range subdomainMap {
		subdomains = append(subdomains, models.Subdomain{
			Name:   subdomain,
			Domain: domain,
			Source: source,
		})
	}
	result.UniqueCount = len(subdomains)

	fmt.Printf("Found %d unique subdomains (total: %d)\n", result.UniqueCount, result.TotalFound)

	// Step 4: Resolve DNS and classify dangling entries
	if len(subdomains) > 0 {
		fmt.Printf("Resolving DNS for %d subdomains...\n", len(subdomains))
		resolvedSubdomains, err := ResolveBatch(ctx, subdomains, cfg.DigPath)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		result.Subdomains = resolvedSubdomains

		// Calculate counts
		for _, sub := range result.Subdomains {
			if sub.Resolved {
				result.ResolvedCount++
			}
			if sub.IsDangling {
				result.DanglingCount++
			}
		}
	}

	fmt.Printf("Resolution complete: %d resolved, %d dangling\n", result.ResolvedCount, result.DanglingCount)

	return result, nil
}

// normalizeSubdomain normalizes a subdomain for deduplication.
// It converts to lowercase, strips trailing dots and whitespace.
// Returns empty string for invalid entries (wildcards).
func normalizeSubdomain(subdomain string) string {
	// Trim whitespace
	s := strings.TrimSpace(subdomain)

	// Skip wildcards
	if strings.HasPrefix(s, "*") {
		return ""
	}

	// Convert to lowercase
	s = strings.ToLower(s)

	// Strip trailing dot
	s = strings.TrimSuffix(s, ".")

	return s
}
