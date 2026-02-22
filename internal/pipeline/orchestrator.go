package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/hakim/reconpipe/internal/config"
	"github.com/hakim/reconpipe/internal/models"
	"github.com/hakim/reconpipe/internal/storage"
)

// StoreInterface is the minimal bbolt contract required by the orchestrator.
// Using an interface keeps the package testable without a real database.
type StoreInterface interface {
	SaveScan(meta *models.ScanMeta) error
	ListScans(target string) ([]*models.ScanMeta, error)
	UpdateScanStatus(id string, status models.ScanStatus) error
}

// StageFunc is the signature each pipeline stage must satisfy.
// ctx carries the deadline; scanDir is the root directory for all I/O.
type StageFunc func(ctx context.Context, scanDir string) error

// Stage pairs a human-readable name with its execution function.
type Stage struct {
	Name string
	Run  StageFunc
}

// PipelineConfig controls how RunPipeline behaves for a single run.
type PipelineConfig struct {
	// Target is the domain being scanned. Required.
	Target string

	// ScanDir is the directory to use for all stage I/O.
	// If empty, a new directory is created via storage.CreateScanDir.
	ScanDir string

	// Stages is the ordered allow-list of stage names to run.
	// Empty means "run all stages defined in allStages".
	Stages []string

	// Skip is a list of stage names to exclude, applied after Stages filtering.
	Skip []string

	// Resume instructs the orchestrator to look up the most recent scan for
	// Target and skip any stages already recorded in its StagesRun list.
	Resume bool

	// Timeout caps the total wall-clock time for all stages combined.
	// Zero means no timeout beyond the caller's context.
	Timeout time.Duration

	// OnStageStart is called immediately before each stage executes.
	// index is 0-based; total is the count of stages selected to run.
	OnStageStart func(name string, index, total int)

	// OnStageDone is called immediately after each stage returns (or panics).
	// err is nil on success; elapsed is the wall time for that stage alone.
	OnStageDone func(name string, index, total int, err error, elapsed time.Duration)
}

// PipelineResult summarises what happened after RunPipeline returns.
type PipelineResult struct {
	// Target is the domain that was scanned.
	Target string

	// ScanDir is the directory that holds all stage output.
	ScanDir string

	// ScanID is the bbolt record ID created (or resumed) for this run.
	ScanID string

	// StagesRun contains the names of stages that were attempted (panics included).
	StagesRun []string

	// StageErrors maps stage name to error message for every stage that failed.
	// Stages not present here completed without error.
	StageErrors map[string]string

	// Elapsed is the total wall time from the first stage to the last.
	Elapsed time.Duration

	// Status is "complete" when every selected stage succeeded, "partial" when
	// at least one stage failed but execution continued past it.
	Status string
}

// RunPipeline orchestrates the full recon pipeline in order.
//
// Stage selection:
//   - allStages defines the canonical order; only stages present in that slice
//     are eligible to run.
//   - cfg.Stages, when non-empty, further restricts which stages run (order
//     is still governed by allStages, not the caller's list).
//   - cfg.Skip removes specific stages from the resulting set.
//   - cfg.Resume skips stages already recorded in the most recent scan's
//     StagesRun list, allowing a crashed run to pick up where it left off.
//
// Crash isolation:
//   Each stage is wrapped in a deferred recover so a panicking stage is
//   recorded as an error and the remaining stages still execute.
//
// The bbolt record is created (StatusRunning) before the first stage and
// updated to StatusComplete or StatusFailed once all stages have been
// attempted.
func RunPipeline(
	ctx context.Context,
	cfg PipelineConfig,
	allStages []Stage,
	store StoreInterface,
	appCfg *config.Config,
) (*PipelineResult, error) {

	// ── 1. Validate required inputs ───────────────────────────────────────────
	if cfg.Target == "" {
		return nil, fmt.Errorf("pipeline: Target is required")
	}
	if store == nil {
		return nil, fmt.Errorf("pipeline: store must not be nil")
	}

	// ── 2. Apply stage filtering ──────────────────────────────────────────────
	selected := filterStages(allStages, cfg.Stages, cfg.Skip)
	if len(selected) == 0 {
		return nil, fmt.Errorf("pipeline: no stages remain after filtering")
	}

	// ── 3. Apply optional timeout ─────────────────────────────────────────────
	runCtx := ctx
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// ── 4. Resolve or create the scan directory ───────────────────────────────
	scanDir := cfg.ScanDir
	startedAt := time.Now()

	if scanDir == "" {
		var err error
		scanDir, err = storage.CreateScanDir(appCfg.ScanDir, cfg.Target, startedAt)
		if err != nil {
			return nil, fmt.Errorf("pipeline: creating scan directory: %w", err)
		}
		fmt.Printf("[*] Created scan directory: %s\n", scanDir)
	}

	// ── 5. Resume: find prior scan and determine already-completed stages ──────
	alreadyDone := map[string]bool{}
	var meta *models.ScanMeta

	if cfg.Resume {
		prior, err := findResumableScan(store, cfg.Target, scanDir)
		if err != nil {
			// Non-fatal: treat as a fresh run with a warning.
			fmt.Printf("[!] Warning: resume lookup failed (%v) — starting fresh\n", err)
		} else if prior != nil {
			meta = prior
			for _, s := range prior.StagesRun {
				alreadyDone[s] = true
			}
			fmt.Printf("[*] Resuming scan %s (%d stages already complete)\n", prior.ID, len(alreadyDone))
		}
	}

	// ── 6. Create or reuse the bbolt scan record ──────────────────────────────
	if meta == nil {
		scan := models.NewScan(cfg.Target)
		scan.ScanDir = scanDir
		scan.Status = models.StatusRunning
		if err := store.SaveScan(&scan.ScanMeta); err != nil {
			return nil, fmt.Errorf("pipeline: saving initial scan record: %w", err)
		}
		meta = &scan.ScanMeta
		fmt.Printf("[*] Scan ID: %s\n", meta.ID)
	} else {
		// Re-mark a previously failed/complete scan as running again.
		if err := store.UpdateScanStatus(meta.ID, models.StatusRunning); err != nil {
			// Non-fatal — we still have the in-memory meta.
			fmt.Printf("[!] Warning: could not update scan status to running: %v\n", err)
		}
	}

	// ── 7. Execute stages ─────────────────────────────────────────────────────
	result := &PipelineResult{
		Target:      cfg.Target,
		ScanDir:     scanDir,
		ScanID:      meta.ID,
		StageErrors: make(map[string]string),
	}

	pipelineStart := time.Now()
	total := len(selected)

	for i, stage := range selected {
		// Skip stages already completed in a prior run.
		if alreadyDone[stage.Name] {
			fmt.Printf("[*] Skipping stage %q (already completed)\n", stage.Name)
			continue
		}

		if cfg.OnStageStart != nil {
			cfg.OnStageStart(stage.Name, i, total)
		}

		stageStart := time.Now()
		stageErr := runStageIsolated(runCtx, stage, scanDir)
		stageElapsed := time.Since(stageStart)

		result.StagesRun = append(result.StagesRun, stage.Name)

		if stageErr != nil {
			result.StageErrors[stage.Name] = stageErr.Error()
			fmt.Printf("[!] Stage %q failed (%s): %v\n", stage.Name, stageElapsed.Round(time.Millisecond), stageErr)
		} else {
			fmt.Printf("[+] Stage %q complete (%s)\n", stage.Name, stageElapsed.Round(time.Millisecond))
		}

		if cfg.OnStageDone != nil {
			cfg.OnStageDone(stage.Name, i, total, stageErr, stageElapsed)
		}

		// Persist the updated StagesRun list after each successful stage so that
		// a crash mid-pipeline leaves a recoverable state in bbolt.
		if stageErr == nil {
			meta.StagesRun = appendUnique(meta.StagesRun, stage.Name)
			if err := store.SaveScan(meta); err != nil {
				// Non-fatal: the stage completed — just warn.
				fmt.Printf("[!] Warning: could not persist StagesRun after %q: %v\n", stage.Name, err)
			}
		}
	}

	result.Elapsed = time.Since(pipelineStart)

	// ── 8. Determine final status and persist ─────────────────────────────────
	finalStatus, resultStatus := resolveFinalStatus(result.StagesRun, result.StageErrors, selected)
	result.Status = resultStatus

	if err := store.UpdateScanStatus(meta.ID, finalStatus); err != nil {
		fmt.Printf("[!] Warning: could not update final scan status: %v\n", err)
	}

	fmt.Printf("[*] Pipeline finished in %s — status: %s\n",
		result.Elapsed.Round(time.Millisecond), result.Status)

	return result, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// filterStages applies the allow-list (allowNames) and deny-list (skipNames)
// to allStages, preserving the order defined in allStages.
func filterStages(allStages []Stage, allowNames, skipNames []string) []Stage {
	allowSet := toSet(allowNames)
	skipSet := toSet(skipNames)

	var out []Stage
	for _, s := range allStages {
		// If an allow-list is provided, only include stages in it.
		if len(allowSet) > 0 && !allowSet[s.Name] {
			continue
		}
		if skipSet[s.Name] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// runStageIsolated runs a single stage inside a deferred recover so that a
// panic in stage code is caught and returned as an error rather than crashing
// the orchestrator process.
func runStageIsolated(ctx context.Context, s Stage, scanDir string) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("stage %q panicked: %v", s.Name, r)
		}
	}()
	return s.Run(ctx, scanDir)
}

// findResumableScan returns the most recent scan for target that matches
// scanDir, or falls back to the most recent scan in any state.
// Returns nil (not an error) when no prior scan exists.
func findResumableScan(store StoreInterface, target, scanDir string) (*models.ScanMeta, error) {
	scans, err := store.ListScans(target)
	if err != nil {
		return nil, fmt.Errorf("listing scans for %q: %w", target, err)
	}
	if len(scans) == 0 {
		return nil, nil
	}

	// Prefer a scan whose ScanDir matches — this handles the case where the
	// caller supplies an explicit scan directory for resumption.
	for _, scan := range scans {
		if scan.ScanDir == scanDir {
			return scan, nil
		}
	}

	// Fall back to the newest scan for this target (ListScans returns newest first).
	return scans[0], nil
}

// resolveFinalStatus returns the bbolt ScanStatus and the human-readable
// result status string based on how many stages failed.
func resolveFinalStatus(stagesRun []string, stageErrors map[string]string, selected []Stage) (models.ScanStatus, string) {
	if len(stagesRun) == 0 {
		return models.StatusFailed, "partial"
	}

	// Count stages that were attempted (present in stagesRun).
	attempted := len(stagesRun)
	failed := len(stageErrors)

	if failed == 0 {
		return models.StatusComplete, "complete"
	}

	if failed == attempted {
		// Every attempted stage errored.
		return models.StatusFailed, "partial"
	}

	// Some stages succeeded, some failed.
	_ = selected // referenced to satisfy import; used in filterStages caller
	return models.StatusFailed, "partial"
}

// appendUnique appends s to slice only if it is not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// toSet converts a string slice into a boolean lookup map.
// An empty slice produces an empty (not nil) map.
func toSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}
