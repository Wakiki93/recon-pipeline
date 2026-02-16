package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	ScanDir    string          `mapstructure:"scan_dir"`
	DBPath     string          `mapstructure:"db_path"`
	Tools      ToolsConfig     `mapstructure:"tools"`
	RateLimits RateLimitConfig `mapstructure:"rate_limits"`
	Stages     StagesConfig    `mapstructure:"stages"`
}

// ToolConfig represents configuration for a single tool
type ToolConfig struct {
	Path    string   `mapstructure:"path"`
	Args    []string `mapstructure:"args"`
	Timeout string   `mapstructure:"timeout"`
}

// ToolsConfig contains configuration for all external tools
type ToolsConfig struct {
	Subfinder ToolConfig `mapstructure:"subfinder"`
	Tlsx      ToolConfig `mapstructure:"tlsx"`
	Dig       ToolConfig `mapstructure:"dig"`
	Masscan   ToolConfig `mapstructure:"masscan"`
	Nmap      ToolConfig `mapstructure:"nmap"`
	Httpx     ToolConfig `mapstructure:"httpx"`
	Gowitness ToolConfig `mapstructure:"gowitness"`
	Cdncheck  ToolConfig `mapstructure:"cdncheck"`
	Nuclei    ToolConfig `mapstructure:"nuclei"`
}

// RateLimitConfig contains rate limiting settings for tools
type RateLimitConfig struct {
	SubfinderThreads int `mapstructure:"subfinder_threads"`
	MasscanRate      int `mapstructure:"masscan_rate"`
	NmapMaxParallel  int `mapstructure:"nmap_max_parallel"`
	HttpxThreads     int `mapstructure:"httpx_threads"`
	NucleiThreads    int `mapstructure:"nuclei_threads"`
	NucleiRateLimit  int `mapstructure:"nuclei_rate_limit"`
}

// StagesConfig controls which pipeline stages to run
type StagesConfig struct {
	Enable []string `mapstructure:"enable"`
	Skip   []string `mapstructure:"skip"`
}

// Load reads and parses configuration from a YAML file
// If path is empty, searches for reconpipe.yaml in current directory and ~/.config/reconpipe/
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	if path != "" {
		// Use explicit path
		v.SetConfigFile(path)
	} else {
		// Search for config in default locations
		v.SetConfigName("reconpipe")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")

		homeDir, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(homeDir, ".config", "reconpipe"))
		}
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	var errs []error

	if c.ScanDir == "" {
		errs = append(errs, errors.New("scan_dir cannot be empty"))
	}

	if c.RateLimits.SubfinderThreads <= 0 {
		errs = append(errs, errors.New("subfinder_threads must be positive"))
	}

	if c.RateLimits.MasscanRate <= 0 {
		errs = append(errs, errors.New("masscan_rate must be positive"))
	}

	if c.RateLimits.NmapMaxParallel <= 0 {
		errs = append(errs, errors.New("nmap_max_parallel must be positive"))
	}

	if c.RateLimits.HttpxThreads <= 0 {
		errs = append(errs, errors.New("httpx_threads must be positive"))
	}

	if c.RateLimits.NucleiThreads <= 0 {
		errs = append(errs, errors.New("nuclei_threads must be positive"))
	}

	if c.RateLimits.NucleiRateLimit <= 0 {
		errs = append(errs, errors.New("nuclei_rate_limit must be positive"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
