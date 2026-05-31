package storage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/detectors"
)

// KeysDB provides persistent storage for detected keys with JSON serialization.
type KeysDB struct {
	mu   sync.RWMutex
	keys map[string]*detectors.Result // keyed by raw key string
	path string
}

// dbFile is the on-disk structure for KeysDB.
type dbFile struct {
	Keys      map[string]*detectors.Result `json:"keys"`
	UpdatedAt time.Time                    `json:"updated_at"`
}

// NewKeysDB creates a new in-memory key store. Call Load() to hydrate from disk.
func NewKeysDB(path string) *KeysDB {
	return &KeysDB{
		keys: make(map[string]*detectors.Result),
		path: path,
	}
}

// Load reads the JSON database from disk. Missing files are not an error.
func (db *KeysDB) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := os.ReadFile(db.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("storage: read db: %w", err)
	}

	var f dbFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("storage: unmarshal db: %w", err)
	}

	db.keys = f.Keys
	if db.keys == nil {
		db.keys = make(map[string]*detectors.Result)
	}
	return nil
}

// Save writes the database to disk as JSON.
func (db *KeysDB) Save() error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	f := dbFile{
		Keys:      db.keys,
		UpdatedAt: time.Now().UTC(),
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("storage: marshal db: %w", err)
	}

	// Atomic write: write to temp file, then rename.
	dir := filepath.Dir(db.path)
	tmp, err := os.CreateTemp(dir, ".keysdb-*.tmp")
	if err != nil {
		return fmt.Errorf("storage: create temp: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("storage: write temp: %w", err)
	}
	tmp.Close()

	if err := os.Rename(tmpPath, db.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("storage: rename: %w", err)
	}

	return nil
}

// Merge deduplicates and merges results into the database.
// For each result: if the key doesn't exist, add it. If it does exist,
// update only if the new result has a "better" status.
func (db *KeysDB) Merge(results []detectors.Result) int {
	db.mu.Lock()
	defer db.mu.Unlock()

	added := 0
	for i := range results {
		r := &results[i]
		if r.Key == "" {
			continue
		}
		// Debug: show first few keys
		if added < 3 {
			k := r.Key
			if len(k) > 40 { k = k[:40] }
			fmt.Printf("MERGE DEBUG: key=%q type=%s status=%s\n", k, r.Type, r.Status)
		}

		existing, ok := db.keys[r.Key]
		if !ok {
			db.keys[r.Key] = r
			added++
		} else {
			// Update if new status is better.
			if r.IsBetterStatusThan(existing) {
				db.keys[r.Key] = r
				added++
			} else if r.Status == existing.Status && r.Balance > existing.Balance {
				// Same status but better balance: update.
				db.keys[r.Key] = r
				added++
			}
		}
	}
	return added
}

// Count returns the total number of keys in the database.
func (db *KeysDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.keys)
}

// All returns all results in the database.
func (db *KeysDB) All() []detectors.Result {
	db.mu.RLock()
	defer db.mu.RUnlock()

	results := make([]detectors.Result, 0, len(db.keys))
	for _, r := range db.keys {
		results = append(results, *r)
	}
	return results
}

// ExportCSV writes all keys with balance information to a CSV file.
func (db *KeysDB) ExportCSV(path string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("storage: create csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header.
	if err := w.Write([]string{
		"key", "type", "balance", "status", "source",
		"repo", "path", "raw_url", "line", "timestamp",
	}); err != nil {
		return fmt.Errorf("storage: csv header: %w", err)
	}

	for _, r := range db.keys {
		row := []string{
			r.Key,
			r.Type,
			fmt.Sprintf("%.8f", r.Balance),
			r.Status,
			r.Source,
			r.Repo,
			r.Path,
			r.RawURL,
			r.Line,
			r.Timestamp.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("storage: csv row: %w", err)
		}
	}

	return nil
}

// AlertsJSONL writes keys with balance >= minBalance to a JSONL file
// formatted for telegram alerts.
func (db *KeysDB) AlertsJSONL(path string, minBalance float64) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("storage: create alerts: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)

	type alertLine struct {
		Key       string  `json:"key"`
		Type      string  `json:"type"`
		Balance   float64 `json:"balance"`
		Repo      string  `json:"repo"`
		Path      string  `json:"path"`
		Timestamp string  `json:"timestamp"`
		Alert     string  `json:"alert"`
	}

	for _, r := range db.keys {
		if r.Balance >= minBalance {
			a := alertLine{
				Key:       r.Key,
				Type:      r.Type,
				Balance:   r.Balance,
				Repo:      r.Repo,
				Path:      r.Path,
				Timestamp: r.Timestamp.Format(time.RFC3339),
				Alert:     fmt.Sprintf("KEY_FOUND: %s balance=%.8f in %s/%s", r.Type, r.Balance, r.Repo, r.Path),
			}
			if err := encoder.Encode(a); err != nil {
				return fmt.Errorf("storage: alert jsonl: %w", err)
			}
		}
	}

	return nil
}

// Stats returns summary statistics.
func (db *KeysDB) Stats() map[string]int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	stats := map[string]int{
		"total":      len(db.keys),
		"verified":   0,
		"unverified": 0,
		"empty":      0,
		"error":      0,
		"with_balance": 0,
	}
	for _, r := range db.keys {
		stats[r.Status]++
		if r.HasBalance() {
			stats["with_balance"]++
		}
	}
	return stats
}
