package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"time"

	"github.com/hakim/reconpipe/internal/models"
)

// NucleiClassification holds CVE/CWE and CVSS metadata for a finding.
type NucleiClassification struct {
	CVEID       []string `json:"cve-id"`
	CWEID       []string `json:"cwe-id"`
	CVSSMetrics string   `json:"cvss-metrics"`
	CVSSScore   float64  `json:"cvss-score"`
}

// NucleiResultInfo holds the template info block from nuclei JSONL output.
type NucleiResultInfo struct {
	Name           string                `json:"name"`
	Severity       string                `json:"severity"`
	Description    string                `json:"description"`
	Reference      []string              `json:"reference"`
	Classification *NucleiClassification `json:"classification"`
	Remediation    string                `json:"remediation"`
	Tags           []string              `json:"tags"`
}

// NucleiResult represents one finding from nuclei's JSONL output.
type NucleiResult struct {
	TemplateID    string           `json:"template-id"`
	TemplateURL   string           `json:"template-url"`
	Info          NucleiResultInfo `json:"info"`
	Type          string           `json:"type"`
	Host          string           `json:"host"`
	MatchedAt     string           `json:"matched-at"`
	IP            string           `json:"ip"`
	Timestamp     string           `json:"timestamp"`
	MatcherStatus bool             `json:"matcher-status"`
}

// RunNuclei executes nuclei against the given targets and returns parsed findings.
// Targets are piped via stdin (one per line). Findings are returned as a slice of
// NucleiResult parsed from nuclei's JSONL output stream.
func RunNuclei(ctx context.Context, targets []string, severity string, threads int, rateLimit int, binaryPath string) ([]NucleiResult, error) {
	if len(targets) == 0 {
		return []NucleiResult{}, nil
	}

	// Apply defaults for optional parameters
	if threads <= 0 {
		threads = 25
	}
	if rateLimit <= 0 {
		rateLimit = 150
	}
	if severity == "" {
		severity = "critical,high,medium"
	}

	binary := "nuclei"
	if binaryPath != "" {
		binary = binaryPath
	}

	args := []string{
		"-jsonl",
		"-silent",
		"-severity", severity,
		"-t", strconv.Itoa(threads),
		"-rl", strconv.Itoa(rateLimit),
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 5 * time.Second

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Write targets to stdin and close so nuclei knows input is done
	go func() {
		defer stdinPipe.Close()
		for _, target := range targets {
			fmt.Fprintln(stdinPipe, target)
		}
	}()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			stdoutBuf.Write(scanner.Bytes())
			stdoutBuf.WriteByte('\n')
		}
		stdoutDone <- scanner.Err()
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			stderrBuf.Write(scanner.Bytes())
			stderrBuf.WriteByte('\n')
		}
		stderrDone <- scanner.Err()
	}()

	<-stdoutDone
	<-stderrDone

	err = cmd.Wait()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("command cancelled: %w", ctx.Err())
		}
		exitCode := cmd.ProcessState.ExitCode()
		return nil, fmt.Errorf("nuclei failed with exit code %d: %w\nstderr: %s", exitCode, err, stderrBuf.String())
	}

	// Parse JSONL output — one finding per line
	var results []NucleiResult
	scanner := bufio.NewScanner(bytes.NewReader(stdoutBuf.Bytes()))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal(line, &result); err != nil {
			fmt.Printf("Warning: failed to parse nuclei JSON line: %v\n", err)
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	return results, nil
}

// NucleiResultToVulnerability converts a NucleiResult to a models.Vulnerability.
// Port is extracted from the matched-at URL when present; defaults to 0.
// Severity is mapped from nuclei's string value to the models.Severity enum.
func NucleiResultToVulnerability(nr NucleiResult) models.Vulnerability {
	return models.Vulnerability{
		TemplateID:  nr.TemplateID,
		Name:        nr.Info.Name,
		Severity:    mapSeverity(nr.Info.Severity),
		Host:        nr.Host,
		Port:        extractPort(nr.MatchedAt),
		URL:         nr.MatchedAt,
		Description: nr.Info.Description,
		MatchedAt:   nr.MatchedAt,
	}
}

// mapSeverity converts a nuclei severity string to a models.Severity constant.
// Any unrecognised value falls back to SeverityInfo.
func mapSeverity(s string) models.Severity {
	switch s {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// extractPort parses a port number from a URL string.
// Returns 0 when no explicit port is present or the input is not a valid URL.
func extractPort(rawURL string) int {
	if rawURL == "" {
		return 0
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Port() == "" {
		return 0
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return 0
	}

	return port
}
