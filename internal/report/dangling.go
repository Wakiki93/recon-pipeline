package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/models"
)

// knownProvider maps a CNAME suffix pattern to a human-readable provider label.
// Entries are checked via strings.Contains so the pattern must be a unique
// substring of the CNAME target (e.g. ".azurewebsites.net").
type knownProvider struct {
	suffix string
	label  string
}

// takeoverProviders is evaluated in declaration order; the first match wins.
var takeoverProviders = []knownProvider{
	{".azurewebsites.net", "Azure"},
	{".cloudfront.net", "CloudFront"},
	{".s3.amazonaws.com", "AWS S3"},
	{".s3-website", "AWS S3"},
	{".herokuapp.com", "Heroku"},
	{".github.io", "GitHub Pages"},
	{".netlify.app", "Netlify"},
	{".shopify.com", "Shopify"},
	{".ghost.io", "Ghost"},
	{".pantheon.io", "Pantheon"},
}

// WriteDanglingDNSReport generates a standalone markdown report for all
// dangling DNS subdomains found during any scan (REPT-03).
// It partitions subdomains into high-risk (has CNAME) and low-risk (no CNAME)
// categories and writes the result to outputPath.
func WriteDanglingDNSReport(subdomains []models.Subdomain, outputPath string) error {
	dangling := filterDangling(subdomains)

	var b strings.Builder
	b.WriteString("# Dangling DNS Report\n\n")
	b.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))

	if len(dangling) == 0 {
		b.WriteString("No dangling DNS records found.\n")
		return writeFile(outputPath, b.String())
	}

	highRisk, lowRisk := partitionDanglingByCNAME(dangling)

	// Summary block
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("Total dangling subdomains: %d\n", len(dangling)))
	b.WriteString(fmt.Sprintf("- With CNAME (takeover risk): %d\n", len(highRisk)))
	b.WriteString(fmt.Sprintf("- Without CNAME (stale DNS): %d\n\n", len(lowRisk)))

	// High-risk section
	if len(highRisk) > 0 {
		b.WriteString("## High Risk — Subdomain Takeover Candidates\n\n")
		b.WriteString("These subdomains have CNAME records pointing to services that may be claimable.\n\n")
		b.WriteString("| Subdomain | CNAME Target | Risk |\n")
		b.WriteString("|-----------|-------------|------|\n")
		for _, s := range highRisk {
			cname := getCNAMETarget(s.DNSRecords)
			risk := classifyProvider(cname)
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", s.Name, cname, risk))
		}
		b.WriteString("\n")
	}

	// Low-risk section
	if len(lowRisk) > 0 {
		b.WriteString("## Low Risk — Stale DNS Entries\n\n")
		b.WriteString("These subdomains don't resolve but have no CNAME. They represent cleanup opportunities.\n\n")
		b.WriteString("| Subdomain | Domain |\n")
		b.WriteString("|-----------|--------|\n")
		for _, s := range lowRisk {
			b.WriteString(fmt.Sprintf("| %s | %s |\n", s.Name, s.Domain))
		}
		b.WriteString("\n")
	}

	return writeFile(outputPath, b.String())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// filterDangling returns only subdomains marked IsDangling=true.
func filterDangling(subdomains []models.Subdomain) []models.Subdomain {
	var result []models.Subdomain
	for _, s := range subdomains {
		if s.IsDangling {
			result = append(result, s)
		}
	}
	return result
}

// partitionDanglingByCNAME splits dangling subdomains into those that have a
// CNAME record (higher takeover risk) and those that do not (stale entries).
func partitionDanglingByCNAME(subdomains []models.Subdomain) (highRisk, lowRisk []models.Subdomain) {
	for _, s := range subdomains {
		if hasCNAMERecord(s.DNSRecords) {
			highRisk = append(highRisk, s)
		} else {
			lowRisk = append(lowRisk, s)
		}
	}
	return highRisk, lowRisk
}

// hasCNAMERecord reports whether the DNS record set contains a CNAME entry.
func hasCNAMERecord(records []models.DNSRecord) bool {
	for _, rec := range records {
		if rec.Type == models.DNSRecordCNAME {
			return true
		}
	}
	return false
}

// classifyProvider maps a CNAME target to a known provider label.
// Returns "Unknown" when no pattern matches.
func classifyProvider(cnameTarget string) string {
	lower := strings.ToLower(cnameTarget)
	for _, p := range takeoverProviders {
		if strings.Contains(lower, p.suffix) {
			return p.label
		}
	}
	return "Unknown"
}
