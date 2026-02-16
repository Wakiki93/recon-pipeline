package tools

import (
	"bytes"
	"os/exec"
	"strings"
)

// ToolRequirement represents an external tool dependency
type ToolRequirement struct {
	Name       string // Display name
	Binary     string // Executable name
	Required   bool   // Whether the tool is required
	InstallCmd string // Installation command
	Purpose    string // One-line description
}

// CheckResult represents the result of checking a single tool
type CheckResult struct {
	Tool    ToolRequirement
	Found   bool
	Path    string
	Version string
}

// DefaultTools returns the list of external tools used by reconpipe
func DefaultTools() []ToolRequirement {
	return []ToolRequirement{
		{
			Name:       "subfinder",
			Binary:     "subfinder",
			Required:   true,
			InstallCmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			Purpose:    "Subdomain discovery",
		},
		{
			Name:       "tlsx",
			Binary:     "tlsx",
			Required:   false,
			InstallCmd: "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
			Purpose:    "TLS subdomain discovery",
		},
		{
			Name:       "dig",
			Binary:     "dig",
			Required:   true,
			InstallCmd: "apt install dnsutils (or brew install bind on macOS)",
			Purpose:    "DNS resolution",
		},
		{
			Name:       "cdncheck",
			Binary:     "cdncheck",
			Required:   false,
			InstallCmd: "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
			Purpose:    "CDN detection",
		},
		{
			Name:       "masscan",
			Binary:     "masscan",
			Required:   true,
			InstallCmd: "apt install masscan (or brew install masscan on macOS)",
			Purpose:    "Fast port scanning",
		},
		{
			Name:       "nmap",
			Binary:     "nmap",
			Required:   true,
			InstallCmd: "apt install nmap (or brew install nmap on macOS)",
			Purpose:    "Service fingerprinting",
		},
		{
			Name:       "httpx",
			Binary:     "httpx",
			Required:   true,
			InstallCmd: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
			Purpose:    "HTTP probing",
		},
		{
			Name:       "gowitness",
			Binary:     "gowitness",
			Required:   false,
			InstallCmd: "go install -v github.com/sensepost/gowitness@latest",
			Purpose:    "Screenshot capture",
		},
		{
			Name:       "nuclei",
			Binary:     "nuclei",
			Required:   true,
			InstallCmd: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
			Purpose:    "Vulnerability scanning",
		},
	}
}

// CheckTools checks all tools in the provided list
func CheckTools(tools []ToolRequirement) []CheckResult {
	results := make([]CheckResult, len(tools))
	for i, tool := range tools {
		results[i] = CheckTool(tool)
	}
	return results
}

// CheckTool checks if a single tool is available
func CheckTool(tool ToolRequirement) CheckResult {
	result := CheckResult{
		Tool:  tool,
		Found: false,
	}

	// Try to find the binary in PATH
	path, err := exec.LookPath(tool.Binary)
	if err != nil {
		return result
	}

	result.Found = true
	result.Path = path

	// Try to get version (best effort)
	result.Version = getVersion(tool.Binary)

	return result
}

// getVersion attempts to get the version of a tool
func getVersion(binary string) string {
	// Try common version flags
	versionFlags := []string{"--version", "-version", "-v", "version"}

	for _, flag := range versionFlags {
		cmd := exec.Command(binary, flag)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		err := cmd.Run()
		if err == nil && out.Len() > 0 {
			// Get first line of output
			firstLine := strings.Split(out.String(), "\n")[0]
			// Trim and limit length
			version := strings.TrimSpace(firstLine)
			if len(version) > 50 {
				version = version[:50] + "..."
			}
			return version
		}
	}

	return "unknown"
}
