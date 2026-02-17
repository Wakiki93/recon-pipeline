package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/portscan"
)

// WritePortReport generates a markdown report for port scan results
// and writes it to the specified output path.
func WritePortReport(result *portscan.PortScanResult, outputPath string) error {
	var b strings.Builder

	// Header
	b.WriteString("# Port Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Total hosts:** %d | **CDN filtered:** %d | **Scanned:** %d | **Open ports:** %d\n\n",
		len(result.Hosts), result.CDNCount, result.ScannedCount, result.TotalPorts))

	// CDN Filtered Hosts section
	b.WriteString("## CDN Filtered Hosts\n\n")
	cdnHosts := getCDNHosts(result.Hosts)
	if len(cdnHosts) > 0 {
		b.WriteString("| IP | CDN Provider | Subdomains |\n")
		b.WriteString("|----|--------------|------------|\n")
		for _, host := range cdnHosts {
			subdomains := strings.Join(host.Subdomains, ", ")
			if subdomains == "" {
				subdomains = "-"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", host.IP, host.CDNProvider, subdomains))
		}
	} else {
		b.WriteString("None found.\n")
	}
	b.WriteString("\n")

	// Open Ports by Host section
	b.WriteString("## Open Ports by Host\n\n")
	hostsWithPorts := getNonCDNHosts(result.Hosts)
	if len(hostsWithPorts) > 0 {
		for _, host := range hostsWithPorts {
			// Subsection per host
			subdomains := strings.Join(host.Subdomains, ", ")
			if subdomains == "" {
				subdomains = "unknown"
			}
			b.WriteString(fmt.Sprintf("### %s (%s)\n\n", host.IP, subdomains))

			if len(host.Ports) > 0 {
				b.WriteString("| Port | Protocol | State | Service | Version |\n")
				b.WriteString("|------|----------|-------|---------|----------|\n")
				for _, port := range host.Ports {
					service := port.Service
					if service == "" {
						service = "-"
					}
					version := port.Version
					if version == "" {
						version = "-"
					}
					b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
						port.Number, port.Protocol, port.State, service, version))
				}
			} else {
				b.WriteString("No open ports discovered.\n")
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("No hosts with open ports found.\n\n")
	}

	// Summary section
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Total IPs checked:** %d\n", len(result.Hosts)))
	b.WriteString(fmt.Sprintf("- **CDN filtered:** %d\n", result.CDNCount))
	b.WriteString(fmt.Sprintf("- **Hosts scanned:** %d\n", result.ScannedCount))
	b.WriteString(fmt.Sprintf("- **Hosts with open ports:** %d\n", countHostsWithPorts(hostsWithPorts)))
	b.WriteString(fmt.Sprintf("- **Total unique ports found:** %d\n", result.TotalPorts))

	// Write to file
	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}

	return nil
}

// getCDNHosts returns hosts that are classified as CDN
func getCDNHosts(hosts []models.Host) []models.Host {
	var cdnHosts []models.Host
	for _, host := range hosts {
		if host.IsCDN {
			cdnHosts = append(cdnHosts, host)
		}
	}
	return cdnHosts
}

// getNonCDNHosts returns non-CDN hosts
func getNonCDNHosts(hosts []models.Host) []models.Host {
	var nonCDNHosts []models.Host
	for _, host := range hosts {
		if !host.IsCDN {
			nonCDNHosts = append(nonCDNHosts, host)
		}
	}
	return nonCDNHosts
}

// countHostsWithPorts returns the count of hosts that have at least one open port
func countHostsWithPorts(hosts []models.Host) int {
	count := 0
	for _, host := range hosts {
		if len(host.Ports) > 0 {
			count++
		}
	}
	return count
}
