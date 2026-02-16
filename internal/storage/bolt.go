package storage

import (
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketScans     = "scans"
	bucketScanIndex = "scan_index"
)

// Store wraps a bbolt database for scan metadata persistence
type Store struct {
	db *bbolt.DB
}

// NewStore opens a bbolt database at the given path and initializes required buckets
func NewStore(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	// Create required buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketScans)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketScanIndex)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the bbolt database
func (s *Store) Close() error {
	return s.db.Close()
}
