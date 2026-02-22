package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// NotifyConfig configures where to send completion notifications.
type NotifyConfig struct {
	WebhookURL string // if empty, no notifications
}

// completionPayload is the JSON body posted to the webhook endpoint.
type completionPayload struct {
	Target         string            `json:"target"`
	ScanID         string            `json:"scan_id"`
	Status         string            `json:"status"`
	StagesRun      []string          `json:"stages_run"`
	ElapsedSeconds float64           `json:"elapsed_seconds"`
	Errors         map[string]string `json:"errors"`
}

// SendCompletion posts a JSON payload to the webhook URL with scan results.
// Returns nil if WebhookURL is empty (no-op). Non-fatal — errors are returned
// but callers should treat them as warnings.
func (n *NotifyConfig) SendCompletion(result *PipelineResult) error {
	if n == nil || n.WebhookURL == "" {
		return nil
	}

	payload := completionPayload{
		Target:         result.Target,
		ScanID:         result.ScanID,
		Status:         result.Status,
		StagesRun:      result.StagesRun,
		ElapsedSeconds: result.Elapsed.Seconds(),
		Errors:         result.StageErrors,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: marshaling payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(n.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: posting to %s: %w", n.WebhookURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify: webhook returned non-2xx status %d", resp.StatusCode)
	}

	return nil
}
