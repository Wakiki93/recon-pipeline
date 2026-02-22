package pipeline

import (
	"fmt"
	"net"
	"strings"
)

// ScopeConfig defines allowed scanning boundaries.
// An empty ScopeConfig (no rules) allows any target.
type ScopeConfig struct {
	// AllowedDomains is a list of domain patterns the target must match.
	// Wildcard prefix ("*.example.com") matches any single-label subdomain.
	// Exact entry ("example.com") matches only that literal value.
	AllowedDomains []string

	// AllowedCIDRs is a list of CIDR ranges an IP must fall within.
	AllowedCIDRs []string
}

// ValidateTarget checks if a domain is within scope.
// Returns nil if allowed, error if out of scope.
// If AllowedDomains is empty, everything is allowed.
func (s *ScopeConfig) ValidateTarget(target string) error {
	if len(s.AllowedDomains) == 0 {
		return nil
	}
	for _, pattern := range s.AllowedDomains {
		if domainMatches(target, pattern) {
			return nil
		}
	}
	return fmt.Errorf("target %q is outside allowed scope (domains: %s)",
		target, strings.Join(s.AllowedDomains, ", "))
}

// ValidateIP checks if an IP is within any allowed CIDR range.
// Returns nil if allowed or no CIDRs configured, error if out of scope.
func (s *ScopeConfig) ValidateIP(ip string) error {
	if len(s.AllowedCIDRs) == 0 {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("scope: %q is not a valid IP address", ip)
	}
	for _, cidr := range s.AllowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return nil
		}
	}
	return fmt.Errorf("IP %q is outside allowed CIDR scope (%s)",
		ip, strings.Join(s.AllowedCIDRs, ", "))
}

// domainMatches returns true when target satisfies the scope pattern.
//
//   - "*.example.com" matches "foo.example.com" but not "example.com" or
//     "foo.bar.example.com" (single wildcard label only).
//   - "example.com" matches only the exact string "example.com".
//   - Comparison is case-insensitive.
func domainMatches(target, pattern string) bool {
	target = strings.ToLower(target)
	pattern = strings.ToLower(pattern)

	if !strings.HasPrefix(pattern, "*.") {
		return target == pattern
	}

	// Wildcard: strip "*." prefix and check target ends with the suffix
	// and has exactly one additional label before it.
	suffix := pattern[2:] // e.g. "example.com"
	if !strings.HasSuffix(target, "."+suffix) {
		return false
	}

	// The part before the suffix must be a single label (no dots).
	label := target[:len(target)-len(suffix)-1]
	return len(label) > 0 && !strings.Contains(label, ".")
}
