package httpprobe

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/tools"
)

// HTTPProbeConfig holds all configuration for the HTTP probing pipeline.
type HTTPProbeConfig struct {
	// HttpxPath is the path to the httpx binary. Empty means resolve from PATH.
	HttpxPath string
	// GowitnessPath is the path to the gowitness binary. Empty means resolve from PATH.
	GowitnessPath string
	// HttpxThreads controls the concurrency level for httpx.
	HttpxThreads int
	// GowitnessThreads controls the concurrency level for gowitness screenshot captures.
	GowitnessThreads int
	// ScreenshotDir is the directory where screenshots will be saved.
	ScreenshotDir string
	// SkipScreenshots disables gowitness when true.
	SkipScreenshots bool
}

// HTTPProbeResult contains the aggregated output of the HTTP probing pipeline.
type HTTPProbeResult struct {
	Target        string             `json:"target"`
	Probes        []models.HTTPProbe `json:"probes"`
	LiveCount     int                `json:"live_count"`
	ScreenshotDir string             `json:"screenshot_dir,omitempty"`
}

// RunHTTPProbe orchestrates httpx probing and optional gowitness screenshots
// against all live HTTP/HTTPS endpoints derived from the provided hosts.
//
// Target list construction:
//   - Non-CDN hosts: "{ip}:{port}" for every open port (direct IP probing)
//   - All hosts: "{subdomain}:{port}" for every subdomain+port combination
//
// CDN IPs are excluded from direct IP:port probing but their subdomains are
// still probed by name so CDN-fronted services appear in results.
func RunHTTPProbe(ctx context.Context, hosts []models.Host, cfg HTTPProbeConfig) (*HTTPProbeResult, error) {
	result := &HTTPProbeResult{
		Probes: []models.HTTPProbe{},
	}

	// Derive target from first host's first subdomain (best-effort)
	if len(hosts) > 0 && len(hosts[0].Subdomains) > 0 {
		result.Target = hosts[0].Subdomains[0]
	}

	// Step 1: Build IP:port targets for non-CDN hosts only.
	// CDN IPs should not be port-probed directly — we reach them via subdomains.
	ipPortSeen := make(map[string]bool)
	var ipPortTargets []string

	for _, host := range hosts {
		if host.IsCDN {
			continue
		}
		for _, port := range host.Ports {
			target := fmt.Sprintf("%s:%d", host.IP, port.Number)
			if !ipPortSeen[target] {
				ipPortSeen[target] = true
				ipPortTargets = append(ipPortTargets, target)
			}
		}
	}

	// Step 2: Build subdomain:port targets for all hosts (CDN and non-CDN).
	// This ensures CDN-fronted hostnames are probed by their virtual-host names.
	subPortSeen := make(map[string]bool)
	var subPortTargets []string

	for _, host := range hosts {
		for _, subdomain := range host.Subdomains {
			for _, port := range host.Ports {
				target := fmt.Sprintf("%s:%d", subdomain, port.Number)
				if !subPortSeen[target] {
					subPortSeen[target] = true
					subPortTargets = append(subPortTargets, target)
				}
			}
		}
	}

	// Step 3: Combine target lists (IP:port first, then subdomain:port)
	allTargets := append(ipPortTargets, subPortTargets...)

	if len(allTargets) == 0 {
		fmt.Println("[*] No HTTP probe targets derived from hosts")
		return result, nil
	}

	// Step 4: Run httpx against all targets
	fmt.Printf("[*] Running httpx against %d targets (%d IP:port, %d subdomain:port)...\n",
		len(allTargets), len(ipPortTargets), len(subPortTargets))

	httpxResults, err := tools.RunHttpx(ctx, allTargets, cfg.HttpxThreads, cfg.HttpxPath)
	if err != nil {
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	fmt.Printf("[*] httpx complete, processing %d results...\n", len(httpxResults))

	// Step 5: Convert HttpxResult to models.HTTPProbe
	rawProbes := make([]models.HTTPProbe, 0, len(httpxResults))
	for _, r := range httpxResults {
		port, err := strconv.Atoi(r.Port)
		if err != nil {
			port = 0
		}

		probe := models.HTTPProbe{
			URL:           r.URL,
			StatusCode:    r.StatusCode,
			Title:         r.Title,
			ContentLength: r.ContentLength,
			WebServer:     r.WebServer,
			Technologies:  r.Technologies,
			Host:          r.Input,
			IP:            r.HostIP,
			Port:          port,
		}
		rawProbes = append(rawProbes, probe)
	}

	// Step 6: Deduplicate probes by URL — httpx may return duplicate URLs
	// when the same service is reached via multiple target forms.
	urlSeen := make(map[string]bool)
	var probes []models.HTTPProbe
	for _, probe := range rawProbes {
		if urlSeen[probe.URL] {
			continue
		}
		urlSeen[probe.URL] = true
		probes = append(probes, probe)
	}

	// Step 7: CDN post-tagging — build a lookup map of IP -> CDN info from
	// the input hosts, then stamp matching probes with CDN metadata.
	type cdnInfo struct {
		isCDN       bool
		cdnProvider string
	}
	ipCDN := make(map[string]cdnInfo)
	for _, host := range hosts {
		ipCDN[host.IP] = cdnInfo{
			isCDN:       host.IsCDN,
			cdnProvider: host.CDNProvider,
		}
	}

	for i := range probes {
		if info, ok := ipCDN[probes[i].IP]; ok {
			probes[i].IsCDN = info.isCDN
			probes[i].CDNProvider = info.cdnProvider
		}
	}

	// Step 8: Run gowitness for screenshots of 2xx responses (optional)
	if !cfg.SkipScreenshots {
		var liveURLs []string
		for _, probe := range probes {
			if probe.StatusCode >= 200 && probe.StatusCode < 300 {
				liveURLs = append(liveURLs, probe.URL)
			}
		}

		if len(liveURLs) > 0 {
			fmt.Printf("[*] Running gowitness for %d live services (2xx)...\n", len(liveURLs))
			if err := tools.RunGowitness(ctx, liveURLs, cfg.ScreenshotDir, cfg.GowitnessThreads, cfg.GowitnessPath); err != nil {
				// Screenshots are best-effort — warn but do not fail the pipeline
				fmt.Printf("[!] Warning: gowitness failed: %v\n", err)
			} else {
				fmt.Printf("[+] Screenshots saved to %s\n", cfg.ScreenshotDir)
			}
		}
	}

	// Step 9: Populate result and return
	result.Probes = probes
	result.LiveCount = len(probes)
	result.ScreenshotDir = cfg.ScreenshotDir

	fmt.Printf("[+] HTTP probe complete: %d live services found\n", result.LiveCount)

	return result, nil
}
