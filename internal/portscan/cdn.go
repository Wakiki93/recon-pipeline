package portscan

import (
	"context"
	"fmt"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// CDNFilterResult contains the results of CDN filtering
type CDNFilterResult struct {
	CDNHosts        []models.Host         `json:"cdn_hosts"`
	ScannableIPs    []string              `json:"scannable_ips"`
	IPToSubdomains  map[string][]string   `json:"ip_to_subdomains"`
}

// FilterCDN classifies IPs as CDN or scannable and builds the IP-to-subdomain mapping.
// It returns CDN hosts, non-CDN IPs to scan, and the reverse mapping for later use.
func FilterCDN(ctx context.Context, subdomains []models.Subdomain, cdncheckPath string) (*CDNFilterResult, error) {
	result := &CDNFilterResult{
		CDNHosts:       []models.Host{},
		ScannableIPs:   []string{},
		IPToSubdomains: make(map[string][]string),
	}

	// Step 1: Build IP-to-subdomain reverse map from resolved subdomains
	uniqueIPMap := make(map[string]bool)

	for _, sub := range subdomains {
		// Only process resolved subdomains with IPs
		if !sub.Resolved || len(sub.IPs) == 0 {
			continue
		}

		for _, ip := range sub.IPs {
			// Add subdomain to reverse map
			result.IPToSubdomains[ip] = append(result.IPToSubdomains[ip], sub.Name)
			// Track unique IPs
			uniqueIPMap[ip] = true
		}
	}

	// Step 2: If no unique IPs, return empty result immediately
	if len(uniqueIPMap) == 0 {
		return result, nil
	}

	// Convert unique IPs map to slice
	uniqueIPs := make([]string, 0, len(uniqueIPMap))
	for ip := range uniqueIPMap {
		uniqueIPs = append(uniqueIPs, ip)
	}

	// Step 3: Call cdncheck
	cdnResults, err := tools.RunCdncheck(ctx, uniqueIPs, cdncheckPath)
	if err != nil {
		return nil, fmt.Errorf("cdncheck execution failed: %w", err)
	}

	// Build a map for quick lookup of CDN results
	cdnMap := make(map[string]tools.CdncheckResult)
	for _, cdnResult := range cdnResults {
		cdnMap[cdnResult.IP] = cdnResult
	}

	// Step 4: Separate results into CDN hosts and scannable IPs
	for _, ip := range uniqueIPs {
		cdnResult, found := cdnMap[ip]

		if found && cdnResult.IsCDN {
			// IP is CDN - create Host object
			host := models.Host{
				IP:          ip,
				IsCDN:       true,
				CDNProvider: cdnResult.CDNName,
				Subdomains:  result.IPToSubdomains[ip],
				Ports:       []models.Port{}, // CDN hosts have no ports scanned
			}
			result.CDNHosts = append(result.CDNHosts, host)
		} else {
			// IP is not CDN or not found in results - add to scannable
			result.ScannableIPs = append(result.ScannableIPs, ip)
		}
	}

	// Step 5: Print progress
	fmt.Printf("[*] CDN check: %d CDN, %d scannable\n", len(result.CDNHosts), len(result.ScannableIPs))

	return result, nil
}
