package tools

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// XML parsing structs for nmap -oX output (unexported - internal parsing details)
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// NmapResult represents the service fingerprint for a single IP:port pair
type NmapResult struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

// RunNmap executes nmap with version detection on specific ports for a single IP.
// It parses XML output and returns structured service/version information.
func RunNmap(ctx context.Context, ip string, ports []int, binaryPath string) ([]NmapResult, error) {
	// Return early if no ports provided
	if len(ports) == 0 {
		return []NmapResult{}, nil
	}

	// Use provided binary path or fall back to tool name
	binary := "nmap"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Build port string: join ports with commas (e.g., "80,443,8080")
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = strconv.Itoa(port)
	}
	portString := strings.Join(portStrings, ",")

	// Create temp file for XML output
	outputFile, err := os.CreateTemp("", "nmap-output-*.xml")
	if err != nil {
		return nil, fmt.Errorf("failed to create output temp file: %w", err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	// Build arguments: -sV (version detection), -Pn (skip ping), -p ports, -oX output, ip
	args := []string{
		"-sV",                 // Version detection
		"-Pn",                 // Skip ping (treat host as online)
		"-p", portString,      // Ports to scan
		"-oX", outputFile.Name(), // XML output
		ip,
	}

	// Execute via RunTool
	_, err = RunTool(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %w", err)
	}

	// Read the XML output file
	data, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read nmap output: %w", err)
	}

	// Parse XML
	var nmapData nmapRun
	if err := xml.Unmarshal(data, &nmapData); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	// Convert parsed XML into flat NmapResult slice
	var results []NmapResult

	for _, host := range nmapData.Hosts {
		// Get the IP address (prefer IPv4, fall back to any address)
		var hostIP string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				hostIP = addr.Addr
				break
			}
		}
		// If no IPv4 found, use first address
		if hostIP == "" && len(host.Addresses) > 0 {
			hostIP = host.Addresses[0].Addr
		}

		// Process ports
		for _, port := range host.Ports.Ports {
			result := NmapResult{
				IP:       hostIP,
				Port:     port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
			}

			// Combine Product and Version for service version
			if port.Service.Product != "" {
				if port.Service.Version != "" {
					result.Version = strings.TrimSpace(port.Service.Product + " " + port.Service.Version)
				} else {
					result.Version = strings.TrimSpace(port.Service.Product)
				}
			}

			// Use service name if product is empty
			if result.Version == "" {
				result.Service = port.Service.Name
			} else {
				result.Service = port.Service.Name
			}

			results = append(results, result)
		}
	}

	return results, nil
}
