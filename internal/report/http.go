package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hakim/reconpipe/internal/httpprobe"
)

// WriteHTTPProbeReport generates a markdown report for HTTP probe results
// and writes it to the specified output path.
func WriteHTTPProbeReport(result *httpprobe.HTTPProbeResult, outputPath string) error {
	var b strings.Builder

	// Header
	b.WriteString("# HTTP Probe Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** %s\n", result.Target))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().UTC().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("**Live services:** %d\n\n", result.LiveCount))

	// Live HTTP Services table
	b.WriteString("## Live HTTP Services\n\n")
	if len(result.Probes) > 0 {
		b.WriteString("| URL | Status | Title | Server | Technologies | CDN |\n")
		b.WriteString("|-----|--------|-------|--------|-------------|-----|\n")
		for _, probe := range result.Probes {
			title := probe.Title
			if title == "" {
				title = "-"
			}

			server := probe.WebServer
			if server == "" {
				server = "-"
			}

			tech := "-"
			if len(probe.Technologies) > 0 {
				tech = strings.Join(probe.Technologies, ", ")
			}

			cdn := "-"
			if probe.IsCDN {
				cdn = probe.CDNProvider
			}

			b.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s |\n",
				probe.URL, probe.StatusCode, title, server, tech, cdn))
		}
	} else {
		b.WriteString("No live HTTP services discovered.\n")
	}
	b.WriteString("\n")

	// Summary section
	screenshotDisplay := "disabled"
	if result.ScreenshotDir != "" {
		screenshotDisplay = result.ScreenshotDir
	}

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Total probes:** %d\n", len(result.Probes)))
	b.WriteString(fmt.Sprintf("- **Live services:** %d\n", result.LiveCount))
	b.WriteString(fmt.Sprintf("- **Screenshots:** %s\n", screenshotDisplay))

	// Write to file
	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}

	return nil
}
