package models

// ScanStatus represents the current state of a scan
type ScanStatus string

const (
	StatusPending  ScanStatus = "pending"
	StatusRunning  ScanStatus = "running"
	StatusComplete ScanStatus = "complete"
	StatusFailed   ScanStatus = "failed"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// DNSRecordType represents different types of DNS records
type DNSRecordType string

const (
	DNSRecordA     DNSRecordType = "A"
	DNSRecordAAAA  DNSRecordType = "AAAA"
	DNSRecordCNAME DNSRecordType = "CNAME"
	DNSRecordMX    DNSRecordType = "MX"
	DNSRecordTXT   DNSRecordType = "TXT"
)
