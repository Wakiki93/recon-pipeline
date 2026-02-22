package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/diff"
	"github.com/hakim/reconpipe/internal/models"
)

// WriteDiffReport generates a markdown report capturing the delta between two
// consecutive scan snapshots and writes it to outputPath.
func WriteDiffReport(result *diff.DiffResult, outputPath string) error {
	var b strings.Builder

	b.WriteString("# Scan Diff Report\n\n")
	b.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))

	// If there are zero changes across all categories, short-circuit.
	if isEmptyDiff(result) {
		b.WriteString("No changes detected.\n")
		return writeFile(outputPath, b.String())
	}

	writeDiffSummaryTable(&b, result)
	writeNewSubdomains(&b, result.NewSubdomains)
	writeRemovedSubdomains(&b, result.RemovedSubdomains)
	writeNewPorts(&b, result.NewPorts)
	writeClosedPorts(&b, result.ClosedPorts)
	writeNewVulns(&b, result.NewVulns)
	writeResolvedVulns(&b, result.ResolvedVulns)
	writeDanglingDNSChanges(&b, result)

	return writeFile(outputPath, b.String())
}

// ---------------------------------------------------------------------------
// Section writers
// ---------------------------------------------------------------------------

// writeDiffSummaryTable writes the three-row comparison table.
func writeDiffSummaryTable(b *strings.Builder, r *diff.DiffResult) {
	b.WriteString("## Summary\n\n")
	b.WriteString("| Category | Previous | Current | Change |\n")
	b.WriteString("|----------|----------|---------|--------|\n")

	subChange := formatChange(r.CurrentSubdomainCount-r.PreviousSubdomainCount, len(r.NewSubdomains), len(r.RemovedSubdomains))
	portChange := formatChange(r.CurrentPortCount-r.PreviousPortCount, len(r.NewPorts), len(r.ClosedPorts))
	vulnChange := formatChange(r.CurrentVulnCount-r.PreviousVulnCount, len(r.NewVulns), len(r.ResolvedVulns))

	b.WriteString(fmt.Sprintf("| Subdomains | %d | %d | %s |\n",
		r.PreviousSubdomainCount, r.CurrentSubdomainCount, subChange))
	b.WriteString(fmt.Sprintf("| Open Ports | %d | %d | %s |\n",
		r.PreviousPortCount, r.CurrentPortCount, portChange))
	b.WriteString(fmt.Sprintf("| Vulnerabilities | %d | %d | %s |\n",
		r.PreviousVulnCount, r.CurrentVulnCount, vulnChange))

	b.WriteString("\n")
}

// writeNewSubdomains renders the new subdomains section. Skipped when empty.
func writeNewSubdomains(b *strings.Builder, subs []models.Subdomain) {
	if len(subs) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## New Subdomains (+%d)\n\n", len(subs)))
	for _, s := range subs {
		b.WriteString(fmt.Sprintf("- %s (%s)\n", s.Name, subdomainDNSSummary(s)))
	}
	b.WriteString("\n")
}

// writeRemovedSubdomains renders the removed subdomains section. Skipped when empty.
func writeRemovedSubdomains(b *strings.Builder, subs []models.Subdomain) {
	if len(subs) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## Removed Subdomains (-%d)\n\n", len(subs)))
	for _, s := range subs {
		b.WriteString(fmt.Sprintf("- %s\n", s.Name))
	}
	b.WriteString("\n")
}

// writeNewPorts renders the new open ports table. Skipped when empty.
func writeNewPorts(b *strings.Builder, changes []diff.PortChange) {
	if len(changes) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## New Open Ports (+%d)\n\n", len(changes)))
	writePortChangeTable(b, changes)
}

// writeClosedPorts renders the closed ports table. Skipped when empty.
func writeClosedPorts(b *strings.Builder, changes []diff.PortChange) {
	if len(changes) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## Closed Ports (-%d)\n\n", len(changes)))
	writePortChangeTable(b, changes)
}

// writePortChangeTable is the shared table renderer for port change slices.
func writePortChangeTable(b *strings.Builder, changes []diff.PortChange) {
	b.WriteString("| Host | IP | Port | Protocol | Service |\n")
	b.WriteString("|------|----|------|----------|---------|\n")
	for _, pc := range changes {
		service := pc.Port.Service
		if service == "" {
			service = "-"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
			pc.Host, pc.IP, pc.Port.Number, pc.Port.Protocol, service))
	}
	b.WriteString("\n")
}

// writeNewVulns renders new vulnerabilities sorted by severity. Skipped when empty.
func writeNewVulns(b *strings.Builder, vulns []models.Vulnerability) {
	if len(vulns) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## New Vulnerabilities (+%d)\n\n", len(vulns)))
	writeVulnTable(b, sortVulnsBySeverity(vulns))
}

// writeResolvedVulns renders resolved vulnerabilities sorted by severity. Skipped when empty.
func writeResolvedVulns(b *strings.Builder, vulns []models.Vulnerability) {
	if len(vulns) == 0 {
		return
	}
	b.WriteString(fmt.Sprintf("## Resolved Vulnerabilities (-%d)\n\n", len(vulns)))
	writeVulnTable(b, sortVulnsBySeverity(vulns))
}

// writeVulnTable is the shared table renderer for vulnerability slices.
func writeVulnTable(b *strings.Builder, vulns []models.Vulnerability) {
	b.WriteString("| Severity | Template ID | Host | Name |\n")
	b.WriteString("|----------|-------------|------|------|\n")
	for _, v := range vulns {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
			v.Severity, v.TemplateID, v.Host, v.Name))
	}
	b.WriteString("\n")
}

// writeDanglingDNSChanges renders the full dangling DNS section with three
// sub-sections. The outer section header is omitted when all three are empty.
func writeDanglingDNSChanges(b *strings.Builder, r *diff.DiffResult) {
	if len(r.NewlyDangling) == 0 && len(r.PersistentlyDangling) == 0 && len(r.ResolvedDangling) == 0 {
		return
	}

	b.WriteString("## Dangling DNS Changes\n\n")

	if len(r.NewlyDangling) > 0 {
		b.WriteString(fmt.Sprintf("### Newly Dangling (%d)\n\n", len(r.NewlyDangling)))
		for _, s := range r.NewlyDangling {
			cname := getCNAMETarget(s.DNSRecords)
			if cname != "-" {
				b.WriteString(fmt.Sprintf("- %s → CNAME: %s\n", s.Name, cname))
			} else {
				b.WriteString(fmt.Sprintf("- %s (no CNAME)\n", s.Name))
			}
		}
		b.WriteString("\n")
	}

	if len(r.PersistentlyDangling) > 0 {
		b.WriteString(fmt.Sprintf("### Persistently Dangling (%d)\n\n", len(r.PersistentlyDangling)))
		for _, s := range r.PersistentlyDangling {
			cname := getCNAMETarget(s.DNSRecords)
			if cname != "-" {
				b.WriteString(fmt.Sprintf("- %s → CNAME: %s\n", s.Name, cname))
			} else {
				b.WriteString(fmt.Sprintf("- %s (no CNAME)\n", s.Name))
			}
		}
		b.WriteString("\n")
	}

	if len(r.ResolvedDangling) > 0 {
		b.WriteString(fmt.Sprintf("### Resolved (%d)\n\n", len(r.ResolvedDangling)))
		for _, s := range r.ResolvedDangling {
			b.WriteString(fmt.Sprintf("- %s (was dangling, now resolves)\n", s.Name))
		}
		b.WriteString("\n")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isEmptyDiff returns true when no changes exist across all categories.
func isEmptyDiff(r *diff.DiffResult) bool {
	return len(r.NewSubdomains) == 0 &&
		len(r.RemovedSubdomains) == 0 &&
		len(r.NewPorts) == 0 &&
		len(r.ClosedPorts) == 0 &&
		len(r.NewVulns) == 0 &&
		len(r.ResolvedVulns) == 0 &&
		len(r.NewlyDangling) == 0 &&
		len(r.PersistentlyDangling) == 0 &&
		len(r.ResolvedDangling) == 0
}

// formatChange returns a human-readable change string such as "+3 / -1".
// When there are no additions and no removals it returns "none".
func formatChange(net, added, removed int) string {
	_ = net // kept for potential future use; additions/removals are more informative
	if added == 0 && removed == 0 {
		return "none"
	}
	parts := make([]string, 0, 2)
	if added > 0 {
		parts = append(parts, fmt.Sprintf("+%d", added))
	}
	if removed > 0 {
		parts = append(parts, fmt.Sprintf("-%d", removed))
	}
	return strings.Join(parts, " / ")
}

// subdomainDNSSummary returns a concise DNS summary string for a subdomain.
// Prefers the first A record; falls back to the CNAME target; returns "-" when
// no records are present.
func subdomainDNSSummary(s models.Subdomain) string {
	// Collect A/AAAA records first
	var ips []string
	for _, rec := range s.DNSRecords {
		if rec.Type == models.DNSRecordA || rec.Type == models.DNSRecordAAAA {
			ips = append(ips, rec.Value)
		}
	}
	if len(ips) > 0 {
		return "A: " + strings.Join(ips, ", ")
	}

	// Fall back to CNAME
	for _, rec := range s.DNSRecords {
		if rec.Type == models.DNSRecordCNAME {
			return "CNAME: " + rec.Value
		}
	}

	return "-"
}

// diffSeverityRank maps a Severity to a sort priority (lower = more severe).
var diffSeverityRank = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

// sortVulnsBySeverity returns a new slice sorted critical-first.
func sortVulnsBySeverity(vulns []models.Vulnerability) []models.Vulnerability {
	sorted := make([]models.Vulnerability, len(vulns))
	copy(sorted, vulns)
	sort.Slice(sorted, func(i, j int) bool {
		ri := diffSeverityRank[sorted[i].Severity]
		rj := diffSeverityRank[sorted[j].Severity]
		if ri != rj {
			return ri < rj
		}
		// Secondary: alphabetical by host for deterministic output
		return sorted[i].Host < sorted[j].Host
	})
	return sorted
}

// writeFile writes content to path, wrapping any OS error with context.
func writeFile(outputPath, content string) error {
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}
	return nil
}
