package discovery

import (
	"context"
	"fmt"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// ResolveBatch resolves DNS for a batch of subdomains and classifies dangling entries.
// For unresolved subdomains, it checks for CNAME records to identify potential takeover candidates.
// Returns updated subdomains slice with resolution data and dangling classification.
func ResolveBatch(ctx context.Context, subdomains []models.Subdomain, digPath string) ([]models.Subdomain, error) {
	// Process each subdomain sequentially
	// (Concurrent resolution can be added later for performance optimization)
	for i := range subdomains {
		// Resolve A/AAAA records
		dnsResults, err := tools.ResolveSubdomains(ctx, []string{subdomains[i].Name}, digPath)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", subdomains[i].Name, err)
		}

		if len(dnsResults) == 0 {
			continue
		}

		dnsResult := dnsResults[0]

		if dnsResult.Resolved {
			// Subdomain resolves - mark as resolved and store IPs
			subdomains[i].Resolved = true
			subdomains[i].IPs = dnsResult.IPs
		} else {
			// Subdomain does not resolve - check for CNAME (dangling DNS candidate)
			cname, err := tools.CheckCNAME(ctx, subdomains[i].Name, digPath)
			if err != nil {
				// Log warning but continue - CNAME check failure shouldn't stop processing
				fmt.Printf("Warning: CNAME check failed for %s: %v\n", subdomains[i].Name, err)
				continue
			}

			// Mark as dangling DNS
			subdomains[i].IsDangling = true

			if cname != "" {
				// High priority: has CNAME (subdomain takeover candidate)
				subdomains[i].DNSRecords = append(subdomains[i].DNSRecords, models.DNSRecord{
					Type:  models.DNSRecordCNAME,
					Value: cname,
				})
			}
			// Low priority: no CNAME (stale DNS cleanup candidate)
			// No additional marking needed - IsDangling=true is sufficient
		}
	}

	return subdomains, nil
}

// ClassifyDangling separates dangling DNS entries into high and low priority.
// High priority: IsDangling=true AND has CNAME record (subdomain takeover candidate)
// Low priority: IsDangling=true AND no CNAME record (stale DNS cleanup)
func ClassifyDangling(subdomains []models.Subdomain) (highPriority, lowPriority []models.Subdomain) {
	for _, sub := range subdomains {
		if !sub.IsDangling {
			continue
		}

		// Check if subdomain has CNAME record
		hasCNAME := false
		for _, record := range sub.DNSRecords {
			if record.Type == models.DNSRecordCNAME {
				hasCNAME = true
				break
			}
		}

		if hasCNAME {
			highPriority = append(highPriority, sub)
		} else {
			lowPriority = append(lowPriority, sub)
		}
	}

	return highPriority, lowPriority
}
