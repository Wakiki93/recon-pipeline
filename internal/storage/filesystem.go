package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// SanitizeTarget replaces characters unsafe for filesystem paths
// Allows alphanumeric, dots, and hyphens. Replaces everything else with underscore.
func SanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9.\-]+`)
	return re.ReplaceAllString(target, "_")
}

// ScanDirPath generates a consistent directory path for a scan
// Format: {baseDir}/{target}_{YYYYMMDD}_{HHMMSS}
func ScanDirPath(baseDir string, target string, startedAt time.Time) string {
	sanitized := SanitizeTarget(target)
	timestamp := startedAt.Format("20060102_150405")
	dirName := fmt.Sprintf("%s_%s", sanitized, timestamp)
	return filepath.Join(baseDir, dirName)
}

// CreateScanDir creates a scan directory with subdirectories for reports and raw output
func CreateScanDir(baseDir string, target string, startedAt time.Time) (string, error) {
	scanPath := ScanDirPath(baseDir, target, startedAt)

	// Create main scan directory
	if err := EnsureDir(scanPath); err != nil {
		return "", err
	}

	// Create subdirectories
	reportsDir := filepath.Join(scanPath, "reports")
	if err := EnsureDir(reportsDir); err != nil {
		return "", err
	}

	rawDir := filepath.Join(scanPath, "raw")
	if err := EnsureDir(rawDir); err != nil {
		return "", err
	}

	return scanPath, nil
}

// EnsureDir creates a directory and all parent directories if they don't exist
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}
