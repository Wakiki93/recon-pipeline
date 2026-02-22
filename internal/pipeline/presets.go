package pipeline

import "fmt"

// Preset defines a named workflow template with pre-configured settings.
type Preset struct {
	Name        string
	Description string
	Stages      []string // which stages to run
	Severity    string   // nuclei severity filter
	SkipPDF     bool
}

// builtinPresets is the registry of all known presets.
var builtinPresets = map[string]Preset{
	"bug-bounty": {
		Name:        "bug-bounty",
		Description: "Full pipeline tuned for bug-bounty programs — all stages, critical/high/medium findings",
		Stages:      []string{"discover", "portscan", "probe", "vulnscan", "diff"},
		Severity:    "critical,high,medium",
		SkipPDF:     false,
	},
	"quick-recon": {
		Name:        "quick-recon",
		Description: "Fast surface-area mapping — discovery and port scan only, no vuln scanning or reports",
		Stages:      []string{"discover", "portscan"},
		Severity:    "",
		SkipPDF:     true,
	},
	"internal-pentest": {
		Name:        "internal-pentest",
		Description: "Deep scan for internal networks — all stages, all severity levels",
		Stages:      []string{"discover", "portscan", "probe", "vulnscan", "diff"},
		Severity:    "critical,high,medium,low",
		SkipPDF:     false,
	},
}

// BuiltinPresets returns the available preset templates.
func BuiltinPresets() map[string]Preset {
	// Return a copy so callers cannot mutate the registry.
	out := make(map[string]Preset, len(builtinPresets))
	for k, v := range builtinPresets {
		out[k] = v
	}
	return out
}

// GetPreset returns a preset by name, or an error if not found.
func GetPreset(name string) (*Preset, error) {
	p, ok := builtinPresets[name]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q — available: bug-bounty, quick-recon, internal-pentest", name)
	}
	cp := p
	return &cp, nil
}
