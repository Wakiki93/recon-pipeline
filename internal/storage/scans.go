package storage

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/hakim/reconpipe/internal/models"
	"go.etcd.io/bbolt"
)

// SaveScan persists a scan metadata record to the database
func (s *Store) SaveScan(meta *models.ScanMeta) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		// Marshal scan metadata to JSON
		data, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		// Store in scans bucket
		scans := tx.Bucket([]byte(bucketScans))
		if err := scans.Put([]byte(meta.ID), data); err != nil {
			return err
		}

		// Update scan index (target -> []scan_id mapping)
		index := tx.Bucket([]byte(bucketScanIndex))
		targetKey := []byte(meta.Target)

		// Get existing scan IDs for this target
		var scanIDs []string
		if existing := index.Get(targetKey); existing != nil {
			if err := json.Unmarshal(existing, &scanIDs); err != nil {
				return err
			}
		}

		// Append new scan ID if not already present
		found := false
		for _, id := range scanIDs {
			if id == meta.ID {
				found = true
				break
			}
		}
		if !found {
			scanIDs = append(scanIDs, meta.ID)
		}

		// Save updated index
		indexData, err := json.Marshal(scanIDs)
		if err != nil {
			return err
		}
		return index.Put(targetKey, indexData)
	})
}

// GetScan retrieves a scan metadata record by ID
func (s *Store) GetScan(id string) (*models.ScanMeta, error) {
	var meta *models.ScanMeta

	err := s.db.View(func(tx *bbolt.Tx) error {
		scans := tx.Bucket([]byte(bucketScans))
		data := scans.Get([]byte(id))
		if data == nil {
			return nil // Not found
		}

		meta = &models.ScanMeta{}
		return json.Unmarshal(data, meta)
	})

	return meta, err
}

// ListScans retrieves all scan metadata records for a target, sorted by StartedAt descending
func (s *Store) ListScans(target string) ([]*models.ScanMeta, error) {
	var scans []*models.ScanMeta

	err := s.db.View(func(tx *bbolt.Tx) error {
		// Get scan IDs from index
		index := tx.Bucket([]byte(bucketScanIndex))
		data := index.Get([]byte(target))
		if data == nil {
			return nil // No scans for this target
		}

		var scanIDs []string
		if err := json.Unmarshal(data, &scanIDs); err != nil {
			return err
		}

		// Retrieve each scan
		scansBucket := tx.Bucket([]byte(bucketScans))
		for _, id := range scanIDs {
			scanData := scansBucket.Get([]byte(id))
			if scanData != nil {
				var meta models.ScanMeta
				if err := json.Unmarshal(scanData, &meta); err != nil {
					return err
				}
				scans = append(scans, &meta)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort by StartedAt descending (newest first)
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt.After(scans[j].StartedAt)
	})

	return scans, nil
}

// GetLatestScan retrieves the most recent scan for a target
func (s *Store) GetLatestScan(target string) (*models.ScanMeta, error) {
	scans, err := s.ListScans(target)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, nil
	}
	return scans[0], nil
}

// UpdateScanStatus updates the status of a scan and sets CompletedAt if applicable
func (s *Store) UpdateScanStatus(id string, status models.ScanStatus) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		scans := tx.Bucket([]byte(bucketScans))

		// Retrieve existing scan
		data := scans.Get([]byte(id))
		if data == nil {
			return nil // Not found, no-op
		}

		var meta models.ScanMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			return err
		}

		// Update status
		meta.Status = status

		// Set CompletedAt if transitioning to terminal state
		if (status == models.StatusComplete || status == models.StatusFailed) && meta.CompletedAt == nil {
			now := time.Now()
			meta.CompletedAt = &now
		}

		// Save updated scan
		updatedData, err := json.Marshal(&meta)
		if err != nil {
			return err
		}
		return scans.Put([]byte(id), updatedData)
	})
}
