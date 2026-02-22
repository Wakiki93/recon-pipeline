// Package diff computes the delta between two scan snapshots.
// It reads the structured JSON output files written by the discovery, portscan,
// and vulnscan stages and produces a DiffResult that identifies what is new,
// removed, or changed between consecutive runs.
package diff

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hakim/reconpipe/internal/models"
)

// ---------------------------------------------------------------------------
// Local wrapper types for JSON unmarshaling.
// These mirror the wrapper structs in the discovery, portscan, and vulnscan
// packages without importing those packages (avoids circular imports).
// ---------------------------------------------------------------------------

type discoveryResult struct {
	Subdomains []models.Subdomain `json:"subdomains"`
}

type portScanResult struct {
	Hosts []models.Host `json:"hosts"`
}

type vulnScanResult struct {
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
}

// ---------------------------------------------------------------------------
// ScanSnapshot
// ---------------------------------------------------------------------------

// ScanSnapshot holds all structured data loaded from a single scan's raw output
// directory. Fields are empty (nil) when the corresponding JSON file is absent.
type ScanSnapshot struct {
	ScanDir         string
	Subdomains      []models.Subdomain
	Hosts           []models.Host
	Vulnerabilities []models.Vulnerability
}

// LoadSnapshot reads the three canonical JSON files from {scanDir}/raw/ and
// populates a ScanSnapshot. Missing files are treated as empty — they are not
// an error condition because early-stage scans may not have all files.
func LoadSnapshot(scanDir string) (*ScanSnapshot, error) {
	snap := &ScanSnapshot{ScanDir: scanDir}

	rawDir := filepath.Join(scanDir, "raw")

	if err := loadSubdomains(rawDir, snap); err != nil {
		return nil, fmt.Errorf("loading subdomains.json: %w", err)
	}

	if err := loadHosts(rawDir, snap); err != nil {
		return nil, fmt.Errorf("loading ports.json: %w", err)
	}

	if err := loadVulns(rawDir, snap); err != nil {
		return nil, fmt.Errorf("loading vulns.json: %w", err)
	}

	return snap, nil
}

func loadSubdomains(rawDir string, snap *ScanSnapshot) error {
	data, err := readOptionalFile(filepath.Join(rawDir, "subdomains.json"))
	if err != nil || data == nil {
		return err
	}

	var wrapper discoveryResult
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	snap.Subdomains = wrapper.Subdomains
	return nil
}

func loadHosts(rawDir string, snap *ScanSnapshot) error {
	data, err := readOptionalFile(filepath.Join(rawDir, "ports.json"))
	if err != nil || data == nil {
		return err
	}

	var wrapper portScanResult
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	snap.Hosts = wrapper.Hosts
	return nil
}

func loadVulns(rawDir string, snap *ScanSnapshot) error {
	data, err := readOptionalFile(filepath.Join(rawDir, "vulns.json"))
	if err != nil || data == nil {
		return err
	}

	var wrapper vulnScanResult
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}

	snap.Vulnerabilities = wrapper.Vulnerabilities
	return nil
}

// readOptionalFile reads a file and returns its bytes. Returns (nil, nil) when
// the file does not exist so callers can treat absence as empty, not as error.
func readOptionalFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// DiffResult
// ---------------------------------------------------------------------------

// PortChange associates a port event with the host on which it occurred.
type PortChange struct {
	Host string
	IP   string
	Port models.Port
}

// DiffResult holds the complete delta between a current and a previous scan
// snapshot. All slice fields are non-nil (empty slices, not nil) so callers
// can range over them unconditionally.
type DiffResult struct {
	// Subdomain changes
	NewSubdomains     []models.Subdomain
	RemovedSubdomains []models.Subdomain

	// Port changes (per-host, per-port)
	NewPorts    []PortChange
	ClosedPorts []PortChange

	// Vulnerability changes
	NewVulns      []models.Vulnerability
	ResolvedVulns []models.Vulnerability

	// Dangling DNS classification
	NewlyDangling        []models.Subdomain // IsDangling=false/absent before, IsDangling=true now
	PersistentlyDangling []models.Subdomain // IsDangling=true in both snapshots
	ResolvedDangling     []models.Subdomain // IsDangling=true before, IsDangling=false/absent now

	// Summary counts (convenient for rendering without re-iterating slices)
	CurrentSubdomainCount  int
	PreviousSubdomainCount int
	CurrentPortCount       int
	PreviousPortCount      int
	CurrentVulnCount       int
	PreviousVulnCount      int
}

// ---------------------------------------------------------------------------
// ComputeDiff
// ---------------------------------------------------------------------------

// ComputeDiff calculates the delta between current and previous snapshots.
// Both arguments must be non-nil; pass an empty ScanSnapshot for the
// "no previous scan" case.
func ComputeDiff(current, previous *ScanSnapshot) *DiffResult {
	dr := &DiffResult{
		NewSubdomains:        []models.Subdomain{},
		RemovedSubdomains:    []models.Subdomain{},
		NewPorts:             []PortChange{},
		ClosedPorts:          []PortChange{},
		NewVulns:             []models.Vulnerability{},
		ResolvedVulns:        []models.Vulnerability{},
		NewlyDangling:        []models.Subdomain{},
		PersistentlyDangling: []models.Subdomain{},
		ResolvedDangling:     []models.Subdomain{},
	}

	diffSubdomains(dr, current.Subdomains, previous.Subdomains)
	diffPorts(dr, current.Hosts, previous.Hosts)
	diffVulns(dr, current.Vulnerabilities, previous.Vulnerabilities)

	// Summary counts
	dr.CurrentSubdomainCount = len(current.Subdomains)
	dr.PreviousSubdomainCount = len(previous.Subdomains)
	dr.CurrentPortCount = totalPortCount(current.Hosts)
	dr.PreviousPortCount = totalPortCount(previous.Hosts)
	dr.CurrentVulnCount = len(current.Vulnerabilities)
	dr.PreviousVulnCount = len(previous.Vulnerabilities)

	return dr
}

// ---------------------------------------------------------------------------
// Subdomain diff
// ---------------------------------------------------------------------------

// diffSubdomains computes new, removed, and dangling changes.
// Key: Subdomain.Name (the fully-qualified subdomain string).
func diffSubdomains(dr *DiffResult, current, previous []models.Subdomain) {
	prevByName := make(map[string]models.Subdomain, len(previous))
	for _, s := range previous {
		prevByName[s.Name] = s
	}

	currByName := make(map[string]models.Subdomain, len(current))
	for _, s := range current {
		currByName[s.Name] = s
	}

	// New and dangling classification relative to previous
	for _, s := range current {
		prev, existed := prevByName[s.Name]
		if !existed {
			dr.NewSubdomains = append(dr.NewSubdomains, s)
			// A brand-new subdomain that is already dangling is NewlyDangling
			if s.IsDangling {
				dr.NewlyDangling = append(dr.NewlyDangling, s)
			}
			continue
		}

		// Subdomain existed before — classify dangling state
		switch {
		case s.IsDangling && !prev.IsDangling:
			dr.NewlyDangling = append(dr.NewlyDangling, s)
		case s.IsDangling && prev.IsDangling:
			dr.PersistentlyDangling = append(dr.PersistentlyDangling, s)
		}
	}

	// Removed: existed before but absent now
	for _, s := range previous {
		if _, exists := currByName[s.Name]; !exists {
			dr.RemovedSubdomains = append(dr.RemovedSubdomains, s)
			// Was dangling and is now gone — counts as resolved dangling
			if s.IsDangling {
				dr.ResolvedDangling = append(dr.ResolvedDangling, s)
			}
		}
	}

	// ResolvedDangling: was dangling, now present but no longer dangling
	for _, s := range current {
		prev, existed := prevByName[s.Name]
		if existed && prev.IsDangling && !s.IsDangling {
			dr.ResolvedDangling = append(dr.ResolvedDangling, s)
		}
	}
}

// ---------------------------------------------------------------------------
// Port diff
// ---------------------------------------------------------------------------

// portKey uniquely identifies a port on a specific IP.
// Format: "ip:number/protocol" (e.g. "192.168.1.1:443/tcp")
func portKey(ip string, p models.Port) string {
	return fmt.Sprintf("%s:%d/%s", ip, p.Number, p.Protocol)
}

// diffPorts computes newly opened and closed ports across all hosts.
func diffPorts(dr *DiffResult, current, previous []models.Host) {
	// Build a flat map of portKey -> PortChange for each snapshot
	prevPorts := make(map[string]PortChange)
	for _, h := range previous {
		for _, p := range h.Ports {
			key := portKey(h.IP, p)
			prevPorts[key] = PortChange{
				Host: primaryHostname(h),
				IP:   h.IP,
				Port: p,
			}
		}
	}

	currPorts := make(map[string]PortChange)
	for _, h := range current {
		for _, p := range h.Ports {
			key := portKey(h.IP, p)
			currPorts[key] = PortChange{
				Host: primaryHostname(h),
				IP:   h.IP,
				Port: p,
			}
		}
	}

	// New ports: in current but not in previous
	for key, pc := range currPorts {
		if _, exists := prevPorts[key]; !exists {
			dr.NewPorts = append(dr.NewPorts, pc)
		}
	}

	// Closed ports: in previous but not in current
	for key, pc := range prevPorts {
		if _, exists := currPorts[key]; !exists {
			dr.ClosedPorts = append(dr.ClosedPorts, pc)
		}
	}
}

// primaryHostname returns the first subdomain associated with the host, or the
// IP address when no subdomains are available.
func primaryHostname(h models.Host) string {
	if len(h.Subdomains) > 0 {
		return h.Subdomains[0]
	}
	return h.IP
}

// totalPortCount sums all ports across all hosts in a snapshot.
func totalPortCount(hosts []models.Host) int {
	total := 0
	for _, h := range hosts {
		total += len(h.Ports)
	}
	return total
}

// ---------------------------------------------------------------------------
// Vulnerability diff
// ---------------------------------------------------------------------------

// vulnKey uniquely identifies a vulnerability finding.
// Format: "templateID::host"
func vulnKey(v models.Vulnerability) string {
	return fmt.Sprintf("%s::%s", v.TemplateID, v.Host)
}

// diffVulns computes new and resolved vulnerabilities.
func diffVulns(dr *DiffResult, current, previous []models.Vulnerability) {
	prevVulns := make(map[string]models.Vulnerability, len(previous))
	for _, v := range previous {
		prevVulns[vulnKey(v)] = v
	}

	currVulns := make(map[string]models.Vulnerability, len(current))
	for _, v := range current {
		currVulns[vulnKey(v)] = v
	}

	// New: in current but not in previous
	for key, v := range currVulns {
		if _, exists := prevVulns[key]; !exists {
			dr.NewVulns = append(dr.NewVulns, v)
		}
	}

	// Resolved: in previous but not in current
	for key, v := range prevVulns {
		if _, exists := currVulns[key]; !exists {
			dr.ResolvedVulns = append(dr.ResolvedVulns, v)
		}
	}
}
