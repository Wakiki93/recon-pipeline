package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() *Config {
	return &Config{
		ScanDir: "scans",
		DBPath:  "reconpipe.db",
		Tools: ToolsConfig{
			Subfinder: ToolConfig{
				Path:    "subfinder",
				Args:    []string{"-silent"},
				Timeout: "5m",
			},
			Tlsx: ToolConfig{
				Path:    "tlsx",
				Args:    []string{"-silent"},
				Timeout: "5m",
			},
			Dig: ToolConfig{
				Path:    "dig",
				Args:    []string{"+short"},
				Timeout: "5m",
			},
			Masscan: ToolConfig{
				Path:    "masscan",
				Args:    []string{"-p1-65535", "--rate=1000"},
				Timeout: "5m",
			},
			Nmap: ToolConfig{
				Path:    "nmap",
				Args:    []string{"-sV", "-Pn"},
				Timeout: "5m",
			},
			Httpx: ToolConfig{
				Path:    "httpx",
				Args:    []string{"-silent"},
				Timeout: "5m",
			},
			Gowitness: ToolConfig{
				Path:    "gowitness",
				Args:    []string{"single"},
				Timeout: "5m",
			},
			Cdncheck: ToolConfig{
				Path:    "cdncheck",
				Args:    []string{"-silent"},
				Timeout: "5m",
			},
			Nuclei: ToolConfig{
				Path:    "nuclei",
				Args:    []string{"-silent"},
				Timeout: "5m",
			},
		},
		RateLimits: RateLimitConfig{
			SubfinderThreads: 10,
			MasscanRate:      1000,
			NmapMaxParallel:  5,
			HttpxThreads:     25,
			NucleiThreads:    10,
			NucleiRateLimit:  150,
		},
		Stages: StagesConfig{
			Enable: []string{},
			Skip:   []string{},
		},
	}
}

// WriteDefault writes a default configuration to the specified path
func WriteDefault(path string) error {
	cfg := DefaultConfig()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
