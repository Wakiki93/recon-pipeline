package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// CdncheckResult represents the CDN/cloud/WAF classification for a single IP
type CdncheckResult struct {
	IP      string `json:"ip"`
	IsCDN   bool   `json:"cdn"`
	CDNName string `json:"cdn_name"`
	IsCloud bool   `json:"cloud"`
	IsWAF   bool   `json:"waf"`
	WAFName string `json:"waf_name"`
}

// RunCdncheck executes cdncheck for the given IPs and returns parsed results.
// It pipes IPs (one per line) to stdin and parses JSONL output.
func RunCdncheck(ctx context.Context, ips []string, binaryPath string) ([]CdncheckResult, error) {
	// Return early if no IPs provided
	if len(ips) == 0 {
		return []CdncheckResult{}, nil
	}

	// Use provided binary path or fall back to tool name
	binary := "cdncheck"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Build arguments: -j (JSON output), -silent
	args := []string{
		"-j",      // JSON output
		"-silent", // Silent mode
	}

	// Create command with context
	cmd := exec.CommandContext(ctx, binary, args...)

	// Set WaitDelay for subprocess cleanup after context cancellation
	cmd.WaitDelay = 5 * time.Second

	// Create pipes for stdin, stdout, and stderr
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

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Write IPs to stdin and close
	go func() {
		defer stdinPipe.Close()
		for _, ip := range ips {
			fmt.Fprintln(stdinPipe, ip)
		}
	}()

	// Read stdout and stderr concurrently to prevent deadlocks
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)

	// Read stdout using bufio.Scanner for line-by-line processing
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			stdoutBuf.Write(scanner.Bytes())
			stdoutBuf.WriteByte('\n')
		}
		stdoutDone <- scanner.Err()
	}()

	// Read stderr
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			stderrBuf.Write(scanner.Bytes())
			stderrBuf.WriteByte('\n')
		}
		stderrDone <- scanner.Err()
	}()

	// Wait for both readers to finish
	<-stdoutDone
	<-stderrDone

	// Wait for the command to complete
	err = cmd.Wait()

	if err != nil {
		// Context cancellation is expected, return error
		if ctx.Err() != nil {
			return nil, fmt.Errorf("command cancelled: %w", ctx.Err())
		}
		// Non-zero exit code
		exitCode := cmd.ProcessState.ExitCode()
		return nil, fmt.Errorf("cdncheck failed with exit code %d: %w\nstderr: %s", exitCode, err, stderrBuf.String())
	}

	// Parse JSONL output (one JSON object per line)
	var results []CdncheckResult
	scanner := bufio.NewScanner(bytes.NewReader(stdoutBuf.Bytes()))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var cdnResult CdncheckResult
		if err := json.Unmarshal(line, &cdnResult); err != nil {
			// Log warning and continue - some lines may not be valid JSON
			fmt.Printf("Warning: failed to parse cdncheck JSON line: %v\n", err)
			continue
		}

		results = append(results, cdnResult)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read cdncheck output: %w", err)
	}

	return results, nil
}
