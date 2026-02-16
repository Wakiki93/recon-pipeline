package models

import (
	"time"

	"github.com/google/uuid"
)

// ScanMeta contains metadata about a scan
type ScanMeta struct {
	ID           string            `json:"id"`
	Target       string            `json:"target"`
	StartedAt    time.Time         `json:"started_at"`
	CompletedAt  *time.Time        `json:"completed_at,omitempty"`
	Status       ScanStatus        `json:"status"`
	ScanDir      string            `json:"scan_dir"`
	ToolVersions map[string]string `json:"tool_versions,omitempty"`
	StagesRun    []string          `json:"stages_run,omitempty"`
}

// Scan represents a complete scan with all discovered data
type Scan struct {
	ScanMeta
	Subdomains      []Subdomain     `json:"subdomains,omitempty"`
	Hosts           []Host          `json:"hosts,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// NewScan creates a new scan instance with initialized metadata
func NewScan(target string) *Scan {
	return &Scan{
		ScanMeta: ScanMeta{
			ID:           uuid.New().String(),
			Target:       target,
			StartedAt:    time.Now(),
			Status:       StatusPending,
			ToolVersions: make(map[string]string),
			StagesRun:    []string{},
		},
		Subdomains:      []Subdomain{},
		Hosts:           []Host{},
		Vulnerabilities: []Vulnerability{},
	}
}
