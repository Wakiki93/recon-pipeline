package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/vulnscan"
)

// severityOrder defines the display order for vulnerability sections (most severe first).
var severityOrder = []models.Severity{
	models.SeverityCritical,
	models.SeverityHigh,
	models.SeverityMedium,
	models.SeverityLow,
	models.SeverityInfo,
}

// WriteVulnReport generates a markdown report for vulnerability scan results
// and writes it to the specified output path.
func WriteVulnReport(result *vulnscan.VulnScanResult, outputPath string) error {
	var b strings.Builder

	// Header
	b.WriteString("# Vulnerability Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf(
		"**Total findings:** %d | **Critical:** %d | **High:** %d | **Medium:** %d | **Low:** %d | **Info:** %d\n\n",
		result.TotalCount,
		result.SeverityCounts[string(models.SeverityCritical)],
		result.SeverityCounts[string(models.SeverityHigh)],
		result.SeverityCounts[string(models.SeverityMedium)],
		result.SeverityCounts[string(models.SeverityLow)],
		result.SeverityCounts[string(models.SeverityInfo)],
	))

	// One section per severity in priority order
	bySeverity := vulnsBySeverity(result.Vulnerabilities)
	for _, sev := range severityOrder {
		heading := strings.Title(string(sev))
		b.WriteString(fmt.Sprintf("## %s Findings\n\n", heading))

		vulns := bySeverity[sev]
		if len(vulns) == 0 {
			b.WriteString(fmt.Sprintf("No %s findings.\n\n", string(sev)))
			continue
		}

		b.WriteString("| Name | Host | Matched At | Template ID |\n")
		b.WriteString("|------|------|------------|-------------|\n")
		for _, v := range vulns {
			matchedAt := v.MatchedAt
			if matchedAt == "" {
				matchedAt = "-"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				v.Name, v.Host, matchedAt, v.TemplateID))
		}
		b.WriteString("\n")
	}

	// Summary section
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Total findings:** %d\n", result.TotalCount))
	b.WriteString(fmt.Sprintf("- **Critical:** %d\n", result.SeverityCounts[string(models.SeverityCritical)]))
	b.WriteString(fmt.Sprintf("- **High:** %d\n", result.SeverityCounts[string(models.SeverityHigh)]))
	b.WriteString(fmt.Sprintf("- **Medium:** %d\n", result.SeverityCounts[string(models.SeverityMedium)]))
	b.WriteString(fmt.Sprintf("- **Low:** %d\n", result.SeverityCounts[string(models.SeverityLow)]))
	b.WriteString(fmt.Sprintf("- **Info:** %d\n", result.SeverityCounts[string(models.SeverityInfo)]))

	// Write to file
	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}

	return nil
}

// vulnsBySeverity partitions a vulnerability slice into a map keyed by severity.
func vulnsBySeverity(vulns []models.Vulnerability) map[models.Severity][]models.Vulnerability {
	groups := make(map[models.Severity][]models.Vulnerability)
	for _, v := range vulns {
		groups[v.Severity] = append(groups[v.Severity], v)
	}
	return groups
}
