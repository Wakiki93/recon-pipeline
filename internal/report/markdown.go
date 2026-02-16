package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/discovery"
	"github.com/hakim/reconpipe/internal/models"
)

// WriteSubdomainReport generates a markdown report for subdomain discovery results
// and writes it to the specified output path.
func WriteSubdomainReport(result *discovery.DiscoveryResult, outputPath string) error {
	var b strings.Builder

	// Header
	b.WriteString("# Subdomain Discovery Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Total discovered:** %d | **Unique:** %d | **Resolved:** %d | **Dangling:** %d\n\n",
		result.TotalFound, result.UniqueCount, result.ResolvedCount, result.DanglingCount))

	// Sources section
	b.WriteString("## Sources\n\n")
	if len(result.Sources) > 0 {
		b.WriteString("| Source | Count |\n")
		b.WriteString("|--------|-------|\n")
		for source, count := range result.Sources {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", source, count))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Resolved subdomains
	b.WriteString("## Resolved Subdomains\n\n")
	resolvedSubdomains := getResolvedSubdomains(result.Subdomains)
	if len(resolvedSubdomains) > 0 {
		b.WriteString("| Subdomain | IPs | Source |\n")
		b.WriteString("|-----------|-----|--------|\n")
		for _, sub := range resolvedSubdomains {
			ips := formatIPs(sub.DNSRecords)
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", sub.Name, ips, sub.Source))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Classify dangling DNS
	highPriority, lowPriority := discovery.ClassifyDangling(result.Subdomains)

	// High priority dangling DNS (CNAME takeover candidates)
	b.WriteString("## Dangling DNS - High Priority (Takeover Candidates)\n\n")
	if len(highPriority) > 0 {
		b.WriteString("| Subdomain | CNAME Target | Source |\n")
		b.WriteString("|-----------|-------------|--------|\n")
		for _, sub := range highPriority {
			target := getCNAMETarget(sub.DNSRecords)
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", sub.Name, target, sub.Source))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Low priority dangling DNS (stale DNS)
	b.WriteString("## Dangling DNS - Low Priority (Stale DNS)\n\n")
	if len(lowPriority) > 0 {
		b.WriteString("| Subdomain | Source |\n")
		b.WriteString("|-----------|--------|\n")
		for _, sub := range lowPriority {
			b.WriteString(fmt.Sprintf("| %s | %s |\n", sub.Name, sub.Source))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Unresolved (no DNS records at all)
	b.WriteString("## Unresolved (No DNS Records)\n\n")
	unresolvedSubdomains := getUnresolvedSubdomains(result.Subdomains)
	if len(unresolvedSubdomains) > 0 {
		b.WriteString("| Subdomain | Source |\n")
		b.WriteString("|-----------|--------|\n")
		for _, sub := range unresolvedSubdomains {
			b.WriteString(fmt.Sprintf("| %s | %s |\n", sub.Name, sub.Source))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Write to file
	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}

	return nil
}

// getResolvedSubdomains returns subdomains that have DNS records with IPs
func getResolvedSubdomains(subdomains []models.Subdomain) []models.Subdomain {
	var resolved []models.Subdomain
	for _, sub := range subdomains {
		if hasIPRecords(sub.DNSRecords) {
			resolved = append(resolved, sub)
		}
	}
	return resolved
}

// getUnresolvedSubdomains returns subdomains with no DNS records at all
func getUnresolvedSubdomains(subdomains []models.Subdomain) []models.Subdomain {
	var unresolved []models.Subdomain
	for _, sub := range subdomains {
		if len(sub.DNSRecords) == 0 {
			unresolved = append(unresolved, sub)
		}
	}
	return unresolved
}

// hasIPRecords checks if DNS records contain any A or AAAA records
func hasIPRecords(records []models.DNSRecord) bool {
	for _, rec := range records {
		if rec.Type == models.DNSRecordA || rec.Type == models.DNSRecordAAAA {
			return true
		}
	}
	return false
}

// formatIPs extracts and formats IP addresses from DNS records
func formatIPs(records []models.DNSRecord) string {
	var ips []string
	for _, rec := range records {
		if rec.Type == models.DNSRecordA || rec.Type == models.DNSRecordAAAA {
			ips = append(ips, rec.Value)
		}
	}
	if len(ips) == 0 {
		return "-"
	}
	return strings.Join(ips, ", ")
}

// getCNAMETarget extracts the CNAME target from DNS records
func getCNAMETarget(records []models.DNSRecord) string {
	for _, rec := range records {
		if rec.Type == models.DNSRecordCNAME {
			return rec.Value
		}
	}
	return "-"
}
