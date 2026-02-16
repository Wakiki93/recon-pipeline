package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// ToolResult contains the result of a tool execution
type ToolResult struct {
	Stdout   []byte
	Stderr   string
	ExitCode int
}

// RunTool executes a tool binary with the given arguments and returns the result.
// It handles concurrent pipe reading to prevent buffer deadlocks and enforces
// context timeout with proper subprocess cleanup.
func RunTool(ctx context.Context, binary string, args ...string) (*ToolResult, error) {
	cmd := exec.CommandContext(ctx, binary, args...)

	// Set WaitDelay for subprocess cleanup after context cancellation
	cmd.WaitDelay = 5 * time.Second

	// Create pipes for stdout and stderr
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

	// Read stderr using io.Copy for complete capture
	go func() {
		_, err := io.Copy(&stderrBuf, stderrPipe)
		stderrDone <- err
	}()

	// Wait for both readers to finish
	<-stdoutDone
	<-stderrDone

	// Wait for the command to complete
	err = cmd.Wait()

	result := &ToolResult{
		Stdout:   stdoutBuf.Bytes(),
		Stderr:   stderrBuf.String(),
		ExitCode: cmd.ProcessState.ExitCode(),
	}

	if err != nil {
		// Context cancellation is expected, return result with error
		if ctx.Err() != nil {
			return result, fmt.Errorf("command cancelled: %w", ctx.Err())
		}
		// Non-zero exit code
		return result, fmt.Errorf("command failed with exit code %d: %w", result.ExitCode, err)
	}

	return result, nil
}
