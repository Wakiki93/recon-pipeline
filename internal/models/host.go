package models

// Subdomain represents a discovered subdomain
type Subdomain struct {
	Name        string      `json:"name"`
	Domain      string      `json:"domain"`
	Source      string      `json:"source"`
	Resolved    bool        `json:"resolved"`
	IPs         []string    `json:"ips,omitempty"`
	DNSRecords  []DNSRecord `json:"dns_records,omitempty"`
	IsCDN       bool        `json:"is_cdn"`
	CDNProvider string      `json:"cdn_provider,omitempty"`
	IsDangling  bool        `json:"is_dangling"`
}

// DNSRecord represents a DNS record entry
type DNSRecord struct {
	Type  DNSRecordType `json:"type"`
	Value string        `json:"value"`
}

// Host represents a discovered host/IP with its services
type Host struct {
	IP          string   `json:"ip"`
	Subdomains  []string `json:"subdomains,omitempty"`
	Ports       []Port   `json:"ports,omitempty"`
	IsCDN       bool     `json:"is_cdn"`
	CDNProvider string   `json:"cdn_provider,omitempty"`
}

// Port represents an open port with service information
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	State    string `json:"state"`
}

// Vulnerability represents a discovered security issue
type Vulnerability struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Host        string   `json:"host"`
	Port        int      `json:"port,omitempty"`
	URL         string   `json:"url,omitempty"`
	Description string   `json:"description,omitempty"`
	MatchedAt   string   `json:"matched_at,omitempty"`
}

// HTTPProbe represents HTTP probe results for a discovered endpoint
type HTTPProbe struct {
	URL            string   `json:"url"`
	StatusCode     int      `json:"status_code"`
	Title          string   `json:"title,omitempty"`
	ContentLength  int64    `json:"content_length"`
	Technologies   []string `json:"technologies,omitempty"`
	Host           string   `json:"host"`
	IP             string   `json:"ip"`
	Port           int      `json:"port"`
	ScreenshotPath string   `json:"screenshot_path,omitempty"`
}
