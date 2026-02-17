package portscan

import (
	"context"
	"fmt"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// PortScanConfig contains configuration for the port scanning pipeline
type PortScanConfig struct {
	CdncheckPath    string
	MasscanPath     string
	NmapPath        string
	MasscanRate     int
	NmapMaxParallel int
	SkipCDNCheck    bool
}

// PortScanResult contains the complete results of port scanning
type PortScanResult struct {
	Target       string        `json:"target"`
	Hosts        []models.Host `json:"hosts"`
	CDNCount     int           `json:"cdn_count"`
	ScannedCount int           `json:"scanned_count"`
	TotalPorts   int           `json:"total_ports"`
}

// RunPortScan orchestrates the full port scanning pipeline.
// It filters CDN IPs, runs masscan for port discovery, nmap for service fingerprinting,
// and returns structured results with all hosts (CDN and scanned).
func RunPortScan(ctx context.Context, subdomains []models.Subdomain, cfg PortScanConfig) (*PortScanResult, error) {
	result := &PortScanResult{
		Hosts: []models.Host{},
	}

	// Derive target from first subdomain's domain field
	if len(subdomains) > 0 {
		result.Target = subdomains[0].Domain
	}

	var cdnFilter *CDNFilterResult
	var err error

	// Step 1: CDN filtering
	if cfg.SkipCDNCheck {
		// Skip cdncheck - treat all IPs as scannable
		fmt.Println("[*] Skipping CDN check (cdncheck not available or disabled)")

		cdnFilter = &CDNFilterResult{
			CDNHosts:       []models.Host{},
			ScannableIPs:   []string{},
			IPToSubdomains: make(map[string][]string),
		}

		// Build IP-to-subdomain map manually (same logic as FilterCDN step 1)
		uniqueIPMap := make(map[string]bool)
		for _, sub := range subdomains {
			if !sub.Resolved || len(sub.IPs) == 0 {
				continue
			}
			for _, ip := range sub.IPs {
				cdnFilter.IPToSubdomains[ip] = append(cdnFilter.IPToSubdomains[ip], sub.Name)
				uniqueIPMap[ip] = true
			}
		}

		// All unique IPs are scannable
		for ip := range uniqueIPMap {
			cdnFilter.ScannableIPs = append(cdnFilter.ScannableIPs, ip)
		}

		fmt.Printf("[*] Found %d IPs to scan\n", len(cdnFilter.ScannableIPs))
	} else {
		fmt.Println("[*] Running CDN detection...")
		cdnFilter, err = FilterCDN(ctx, subdomains, cfg.CdncheckPath)
		if err != nil {
			return nil, fmt.Errorf("CDN filtering failed: %w", err)
		}
	}

	result.CDNCount = len(cdnFilter.CDNHosts)

	// Step 2: If no scannable IPs, return result with only CDN hosts
	if len(cdnFilter.ScannableIPs) == 0 {
		fmt.Println("[*] All IPs are CDN-hosted, skipping port scan")
		result.Hosts = cdnFilter.CDNHosts
		return result, nil
	}

	// Step 3: Run masscan
	fmt.Printf("[*] Running masscan on %d IPs...\n", len(cdnFilter.ScannableIPs))
	masscanResults, err := tools.RunMasscan(ctx, cdnFilter.ScannableIPs, cfg.MasscanRate, cfg.MasscanPath)
	if err != nil {
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}
	fmt.Printf("[*] Masscan complete, processing results...\n")

	// Step 4: If no open ports found, print message and return
	if len(masscanResults) == 0 {
		fmt.Println("[*] No open ports discovered")

		// Create hosts with no ports for all scannable IPs
		for _, ip := range cdnFilter.ScannableIPs {
			host := models.Host{
				IP:         ip,
				Subdomains: cdnFilter.IPToSubdomains[ip],
				Ports:      []models.Port{},
				IsCDN:      false,
			}
			result.Hosts = append(result.Hosts, host)
		}

		// Add CDN hosts
		result.Hosts = append(result.Hosts, cdnFilter.CDNHosts...)
		result.ScannedCount = len(cdnFilter.ScannableIPs)

		return result, nil
	}

	// Step 5: Build IP-to-ports map from masscan results
	ipPorts := make(map[string][]int)
	for _, masscanResult := range masscanResults {
		for _, masscanPort := range masscanResult.Ports {
			// Only include open ports
			if masscanPort.Status == "open" {
				ipPorts[masscanResult.IP] = append(ipPorts[masscanResult.IP], masscanPort.Port)
			}
		}
	}

	// Step 6: Run nmap for service fingerprinting (sequential for now)
	fmt.Printf("[*] Running nmap for service detection on %d hosts...\n", len(ipPorts))

	nmapResultsMap := make(map[string][]tools.NmapResult)

	for ip, ports := range ipPorts {
		if len(ports) == 0 {
			continue
		}

		fmt.Printf("[*] Scanning %s (%d ports)...\n", ip, len(ports))
		nmapResults, err := tools.RunNmap(ctx, ip, ports, cfg.NmapPath)
		if err != nil {
			// Log warning and continue - nmap failure shouldn't stop the pipeline
			fmt.Printf("[!] Warning: nmap failed for %s: %v\n", ip, err)
			continue
		}

		nmapResultsMap[ip] = nmapResults
	}

	// Step 7: Build Host objects with port information
	scannedHosts := make(map[string]bool)

	for ip, nmapResults := range nmapResultsMap {
		host := models.Host{
			IP:         ip,
			Subdomains: cdnFilter.IPToSubdomains[ip],
			Ports:      []models.Port{},
			IsCDN:      false,
		}

		// Convert NmapResult to models.Port
		for _, nmapResult := range nmapResults {
			port := models.Port{
				Number:   nmapResult.Port,
				Protocol: nmapResult.Protocol,
				Service:  nmapResult.Service,
				Version:  nmapResult.Version,
				State:    nmapResult.State,
			}
			host.Ports = append(host.Ports, port)
			result.TotalPorts++
		}

		result.Hosts = append(result.Hosts, host)
		scannedHosts[ip] = true
	}

	// Add hosts with open ports but failed nmap scans (masscan found ports but nmap failed)
	for ip, ports := range ipPorts {
		if scannedHosts[ip] {
			continue
		}

		host := models.Host{
			IP:         ip,
			Subdomains: cdnFilter.IPToSubdomains[ip],
			Ports:      []models.Port{},
			IsCDN:      false,
		}

		// Add ports without service info
		for _, portNum := range ports {
			port := models.Port{
				Number:   portNum,
				Protocol: "tcp",
				State:    "open",
			}
			host.Ports = append(host.Ports, port)
			result.TotalPorts++
		}

		result.Hosts = append(result.Hosts, host)
		scannedHosts[ip] = true
	}

	// Add hosts with no open ports
	for _, ip := range cdnFilter.ScannableIPs {
		if scannedHosts[ip] {
			continue
		}

		host := models.Host{
			IP:         ip,
			Subdomains: cdnFilter.IPToSubdomains[ip],
			Ports:      []models.Port{},
			IsCDN:      false,
		}
		result.Hosts = append(result.Hosts, host)
	}

	// Step 8: Add CDN hosts to result
	result.Hosts = append(result.Hosts, cdnFilter.CDNHosts...)
	result.ScannedCount = len(cdnFilter.ScannableIPs)

	fmt.Printf("[+] Port scan complete: %d hosts scanned, %d ports found\n", result.ScannedCount, result.TotalPorts)

	return result, nil
}
