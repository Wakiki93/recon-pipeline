package main

// stages.go — shared stage-builder used by both the scan command and the
// wizard command.  The five closures here are identical to what scan.go used
// to define inline; extracting them avoids duplication.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hakim/reconpipe/internal/diff"
	"github.com/hakim/reconpipe/internal/discovery"
	"github.com/hakim/reconpipe/internal/httpprobe"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/pipeline"
	"github.com/hakim/reconpipe/internal/portscan"
	"github.com/hakim/reconpipe/internal/report"
	"github.com/hakim/reconpipe/internal/storage"
	"github.com/hakim/reconpipe/internal/vulnscan"
)

// buildScanStages constructs the five canonical pipeline stages as closures
// that capture all the runtime parameters they need.  The returned slice is
// in canonical execution order: discover, portscan, probe, vulnscan, diff.
//
// Parameters mirror the local variables that scan.go computed from flags and
// tool-check results so the wizard can pass the same values without re-running
// tool checks.
func buildScanStages(
	domain string,
	severity string,
	skipPDF bool,
	python3Available bool,
	pythonBinary string,
	tlsxAvailable bool,
	cdncheckAvailable bool,
	gowitnessAvailable bool,
	nucleiAvailable bool,
) []pipeline.Stage {

	discoverStage := pipeline.Stage{
		Name: "discover",
		Run: func(ctx context.Context, scanDir string) error {
			if err := storage.EnsureDir(filepath.Join(scanDir, "raw")); err != nil {
				return fmt.Errorf("ensuring raw dir: %w", err)
			}
			if err := storage.EnsureDir(filepath.Join(scanDir, "reports")); err != nil {
				return fmt.Errorf("ensuring reports dir: %w", err)
			}

			discoveryCfg := discovery.DiscoveryConfig{
				SubfinderThreads: cfg.RateLimits.SubfinderThreads,
				SubfinderPath:    "",
				TlsxPath:         "",
				DigPath:          "",
				SkipTlsx:         !tlsxAvailable,
			}

			result, err := discovery.RunDiscovery(ctx, domain, discoveryCfg)
			if err != nil {
				return fmt.Errorf("discovery pipeline: %w", err)
			}

			fmt.Printf("    [>] Found %d unique subdomains (%d resolved, %d dangling)\n",
				result.UniqueCount, result.ResolvedCount, result.DanglingCount)

			reportPath := filepath.Join(scanDir, "reports", "subdomains.md")
			if err := report.WriteSubdomainReport(result, reportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write subdomain report: %v\n", err)
			}

			rawPath := filepath.Join(scanDir, "raw", "subdomains.json")
			rawData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling subdomains: %w", err)
			}
			return os.WriteFile(rawPath, rawData, 0644)
		},
	}

	portscanStage := pipeline.Stage{
		Name: "portscan",
		Run: func(ctx context.Context, scanDir string) error {
			subdomainsPath := filepath.Join(scanDir, "raw", "subdomains.json")
			subData, err := os.ReadFile(subdomainsPath)
			if err != nil {
				return fmt.Errorf("reading subdomains.json (run discover first): %w", err)
			}

			var discoveryResult discovery.DiscoveryResult
			if err := json.Unmarshal(subData, &discoveryResult); err != nil {
				return fmt.Errorf("parsing subdomains.json: %w", err)
			}

			var resolved []models.Subdomain
			for _, sub := range discoveryResult.Subdomains {
				if sub.Resolved && len(sub.IPs) > 0 {
					resolved = append(resolved, sub)
				}
			}

			if len(resolved) == 0 {
				fmt.Println("    [!] No resolved subdomains with IPs — skipping port scan")
				empty := portscan.PortScanResult{Target: domain, Hosts: []models.Host{}}
				rawData, _ := json.MarshalIndent(empty, "", "  ")
				rawPath := filepath.Join(scanDir, "raw", "ports.json")
				return os.WriteFile(rawPath, rawData, 0644)
			}

			fmt.Printf("    [>] Scanning %d resolved subdomains\n", len(resolved))

			portScanCfg := portscan.PortScanConfig{
				CdncheckPath:    "",
				MasscanPath:     "",
				NmapPath:        "",
				MasscanRate:     cfg.RateLimits.MasscanRate,
				NmapMaxParallel: cfg.RateLimits.NmapMaxParallel,
				SkipCDNCheck:    !cdncheckAvailable,
			}

			result, err := portscan.RunPortScan(ctx, resolved, portScanCfg)
			if err != nil {
				return fmt.Errorf("port scan pipeline: %w", err)
			}

			fmt.Printf("    [>] CDN: %d filtered, scanned: %d, open ports: %d\n",
				result.CDNCount, result.ScannedCount, result.TotalPorts)

			reportPath := filepath.Join(scanDir, "reports", "ports.md")
			if err := report.WritePortReport(result, reportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write port report: %v\n", err)
			}

			rawPath := filepath.Join(scanDir, "raw", "ports.json")
			rawData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling port scan result: %w", err)
			}
			return os.WriteFile(rawPath, rawData, 0644)
		},
	}

	probeStage := pipeline.Stage{
		Name: "probe",
		Run: func(ctx context.Context, scanDir string) error {
			portsPath := filepath.Join(scanDir, "raw", "ports.json")
			portsData, err := os.ReadFile(portsPath)
			if err != nil {
				return fmt.Errorf("reading ports.json (run portscan first): %w", err)
			}

			var portResult portscan.PortScanResult
			if err := json.Unmarshal(portsData, &portResult); err != nil {
				return fmt.Errorf("parsing ports.json: %w", err)
			}

			hosts := hostsWithOpenPorts(portResult.Hosts)
			if len(hosts) == 0 {
				fmt.Println("    [!] No hosts with open ports — skipping HTTP probe")
				empty := httpprobe.HTTPProbeResult{Target: domain, Probes: []models.HTTPProbe{}}
				rawData, _ := json.MarshalIndent(empty, "", "  ")
				rawPath := filepath.Join(scanDir, "raw", "http-probes.json")
				return os.WriteFile(rawPath, rawData, 0644)
			}

			fmt.Printf("    [>] Probing %d hosts\n", len(hosts))

			screenshotDir := filepath.Join(scanDir, "screenshots")
			skipScreenshots := !gowitnessAvailable
			if !skipScreenshots {
				if err := storage.EnsureDir(screenshotDir); err != nil {
					fmt.Printf("    [!] Warning: could not create screenshot dir: %v\n", err)
					skipScreenshots = true
				}
			}

			probeCfg := httpprobe.HTTPProbeConfig{
				HttpxPath:        "",
				GowitnessPath:    "",
				HttpxThreads:     cfg.RateLimits.HttpxThreads,
				GowitnessThreads: 6,
				ScreenshotDir:    screenshotDir,
				SkipScreenshots:  skipScreenshots,
			}

			probeResult, err := httpprobe.RunHTTPProbe(ctx, hosts, probeCfg)
			if err != nil {
				return fmt.Errorf("HTTP probe pipeline: %w", err)
			}
			if probeResult.Target == "" {
				probeResult.Target = domain
			}

			fmt.Printf("    [>] Live services: %d\n", probeResult.LiveCount)

			reportPath := filepath.Join(scanDir, "reports", "http-probes.md")
			if err := report.WriteHTTPProbeReport(probeResult, reportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write HTTP probe report: %v\n", err)
			}

			rawPath := filepath.Join(scanDir, "raw", "http-probes.json")
			rawData, err := json.MarshalIndent(probeResult, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling HTTP probe result: %w", err)
			}
			return os.WriteFile(rawPath, rawData, 0644)
		},
	}

	vulnscanStage := pipeline.Stage{
		Name: "vulnscan",
		Run: func(ctx context.Context, scanDir string) error {
			if !nucleiAvailable {
				fmt.Println("    [!] nuclei not found — skipping vulnerability scan")
				return nil
			}

			portsPath := filepath.Join(scanDir, "raw", "ports.json")
			portsData, err := os.ReadFile(portsPath)
			if err != nil {
				return fmt.Errorf("reading ports.json (run portscan first): %w", err)
			}
			var portResult portscan.PortScanResult
			if err := json.Unmarshal(portsData, &portResult); err != nil {
				return fmt.Errorf("parsing ports.json: %w", err)
			}

			probesPath := filepath.Join(scanDir, "raw", "http-probes.json")
			probesData, err := os.ReadFile(probesPath)
			if err != nil {
				return fmt.Errorf("reading http-probes.json (run probe first): %w", err)
			}
			var probeResult httpprobe.HTTPProbeResult
			if err := json.Unmarshal(probesData, &probeResult); err != nil {
				return fmt.Errorf("parsing http-probes.json: %w", err)
			}

			fmt.Printf("    [>] Scanning %d hosts, %d HTTP probes (severity: %s)\n",
				len(portResult.Hosts), len(probeResult.Probes), severity)

			vulnCfg := vulnscan.VulnScanConfig{
				NucleiPath: "",
				Severity:   severity,
				Threads:    cfg.RateLimits.NucleiThreads,
				RateLimit:  cfg.RateLimits.NucleiRateLimit,
			}

			result, err := vulnscan.RunVulnScan(ctx, portResult.Hosts, probeResult.Probes, vulnCfg)
			if err != nil {
				return fmt.Errorf("vulnerability scan pipeline: %w", err)
			}
			if result.Target == "" {
				result.Target = domain
			}

			fmt.Printf("    [>] Total findings: %d\n", result.TotalCount)

			reportPath := filepath.Join(scanDir, "reports", "vulns.md")
			if err := report.WriteVulnReport(result, reportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write vuln report: %v\n", err)
			}

			rawPath := filepath.Join(scanDir, "raw", "vulns.json")
			rawData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling vuln result: %w", err)
			}
			if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
				return fmt.Errorf("writing vulns.json: %w", err)
			}

			jsonlPath := filepath.Join(scanDir, "raw", "nuclei-output.jsonl")
			if err := writeNucleiJSONL(result.Vulnerabilities, jsonlPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write nuclei JSONL: %v\n", err)
			}

			if !skipPDF && python3Available {
				pdfPath := filepath.Join(scanDir, "reports", "vulns.pdf")
				generateNucPDF(ctx, pythonBinary, jsonlPath, pdfPath, domain)
			}

			return nil
		},
	}

	diffStage := pipeline.Stage{
		Name: "diff",
		Run: func(ctx context.Context, scanDir string) error {
			currentSnap, err := diff.LoadSnapshot(scanDir)
			if err != nil {
				return fmt.Errorf("loading current snapshot: %w", err)
			}

			diffStore, err := storage.NewStore(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("opening database for diff: %w", err)
			}
			defer diffStore.Close()

			prevDir, err := findPreviousScanDir(domain, scanDir)
			if err != nil {
				fmt.Printf("    [!] Warning: could not find previous scan: %v\n", err)
				return nil
			}
			if prevDir == "" {
				fmt.Println("    [>] No previous scan found — skipping diff")
				return nil
			}

			fmt.Printf("    [>] Comparing against %s\n", prevDir)

			previousSnap, err := diff.LoadSnapshot(prevDir)
			if err != nil {
				return fmt.Errorf("loading previous snapshot: %w", err)
			}

			result := diff.ComputeDiff(currentSnap, previousSnap)

			diffReportPath := filepath.Join(scanDir, "reports", "diff.md")
			if err := report.WriteDiffReport(result, diffReportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write diff report: %v\n", err)
			}

			danglingReportPath := filepath.Join(scanDir, "reports", "dangling-dns.md")
			if err := report.WriteDanglingDNSReport(currentSnap.Subdomains, danglingReportPath); err != nil {
				fmt.Printf("    [!] Warning: failed to write dangling DNS report: %v\n", err)
			}

			rawPath := filepath.Join(scanDir, "raw", "diff.json")
			rawData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling diff result: %w", err)
			}
			if err := os.WriteFile(rawPath, rawData, 0644); err != nil {
				return fmt.Errorf("writing diff.json: %w", err)
			}

			fmt.Printf("    [>] Subdomains: +%d new, -%d removed | Ports: +%d new, -%d closed | Vulns: +%d new, -%d resolved\n",
				len(result.NewSubdomains), len(result.RemovedSubdomains),
				len(result.NewPorts), len(result.ClosedPorts),
				len(result.NewVulns), len(result.ResolvedVulns))

			return nil
		},
	}

	return []pipeline.Stage{
		discoverStage,
		portscanStage,
		probeStage,
		vulnscanStage,
		diffStage,
	}
}
