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

// HttpxResult represents the probed HTTP endpoint data returned by httpx
type HttpxResult struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	ContentLength int64    `json:"content_length"`
	WebServer     string   `json:"webserver"`
	Technologies  []string `json:"tech"`
	HostIP        string   `json:"host"`
	Port          string   `json:"port"`
	CDN           bool     `json:"cdn"`
	CDNName       string   `json:"cdn_name"`
}

// RunHttpx executes httpx for the given targets and returns parsed results.
// It pipes targets to stdin line by line and parses JSONL output.
func RunHttpx(ctx context.Context, targets []string, threads int, binaryPath string) ([]HttpxResult, error) {
	// Return early if no targets provided
	if len(targets) == 0 {
		return []HttpxResult{}, nil
	}

	// Use provided binary path or fall back to tool name
	binary := "httpx"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Default threads to 50 if not specified
	if threads <= 0 {
		threads = 50
	}

	// Build arguments: JSON output, status code, title, server, tech detection, CDN, IP
	args := []string{
		"-json",                           // JSON output (JSONL, one object per line)
		"-silent",                         // Suppress banner and non-essential output
		"-sc",                             // Include status code
		"-title",                          // Include page title
		"-server",                         // Include webserver header
		"-td",                             // Enable technology detection
		"-cdn",                            // Include CDN detection
		"-ip",                             // Include resolved IP
		"-t", fmt.Sprintf("%d", threads),  // Thread count
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

	// Write targets to stdin and close
	go func() {
		defer stdinPipe.Close()
		for _, target := range targets {
			fmt.Fprintln(stdinPipe, target)
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
		return nil, fmt.Errorf("httpx failed with exit code %d: %w\nstderr: %s", exitCode, err, stderrBuf.String())
	}

	// Parse JSONL output (one JSON object per line)
	var results []HttpxResult
	scanner := bufio.NewScanner(bytes.NewReader(stdoutBuf.Bytes()))

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var httpxResult HttpxResult
		if err := json.Unmarshal(line, &httpxResult); err != nil {
			// Log warning and continue - some lines may not be valid JSON
			fmt.Printf("Warning: failed to parse httpx JSON line: %v\n", err)
			continue
		}

		results = append(results, httpxResult)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read httpx output: %w", err)
	}

	return results, nil
}
