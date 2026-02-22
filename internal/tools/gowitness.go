package tools

import (
	"context"
	"fmt"
	"os"
)

// RunGowitness executes gowitness to capture screenshots for the given URLs.
// It writes URLs to a temp file, creates the screenshot directory, then runs
// gowitness in file-scan mode. Screenshot filenames are managed by gowitness itself.
// Returns an error only — gowitness is fire-and-forget for screenshot capture.
func RunGowitness(ctx context.Context, urls []string, screenshotDir string, threads int, binaryPath string) error {
	// Return early if no URLs provided
	if len(urls) == 0 {
		return nil
	}

	// Use provided binary path or fall back to tool name
	binary := "gowitness"
	if binaryPath != "" {
		binary = binaryPath
	}

	// Default threads to 4 if not specified
	if threads <= 0 {
		threads = 4
	}

	// Ensure the screenshot directory exists before invoking gowitness
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return fmt.Errorf("failed to create screenshot directory %q: %w", screenshotDir, err)
	}

	// Create temp file for input URLs
	inputFile, err := os.CreateTemp("", "gowitness-input-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create input temp file: %w", err)
	}
	defer os.Remove(inputFile.Name())

	// Write URLs to temp file (one per line)
	for _, url := range urls {
		if _, err := fmt.Fprintln(inputFile, url); err != nil {
			inputFile.Close()
			return fmt.Errorf("failed to write URL to temp file: %w", err)
		}
	}
	inputFile.Close()

	// Build arguments for gowitness file-scan mode
	args := []string{
		"scan", "file",
		"-f", inputFile.Name(),           // Input file of URLs
		"-s", screenshotDir,              // Screenshot output directory
		"-t", fmt.Sprintf("%d", threads), // Concurrent thread count
		"-T", "60",                       // Per-page timeout in seconds
		"--screenshot-format", "png",     // Output format
	}

	// Execute via RunTool (no stdin piping needed)
	_, err = RunTool(ctx, binary, args...)
	if err != nil {
		// Context cancellation propagates as-is
		if ctx.Err() != nil {
			return fmt.Errorf("gowitness cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("gowitness execution failed: %w", err)
	}

	return nil
}
