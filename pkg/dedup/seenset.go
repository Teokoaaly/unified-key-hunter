package dedup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SeenSet is a thread-safe deduplication set backed by an in-memory map
// and a flat file for persistence. Each key is written to the file
// immediately upon Add so the file can be used across restarts.
type SeenSet struct {
	mu       sync.RWMutex
	seen     map[string]bool
	file     *os.File
	filePath string
}

// NewSeenSet creates a new SeenSet. It loads existing keys from the file
// at path (if it exists) and opens it for appending. The file is created
// if it does not exist. Directory is created if needed.
func NewSeenSet(path string) (*SeenSet, error) {
	// Ensure the parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("dedup: failed to create directory %s: %w", dir, err)
	}

	// Open file for read+append (create if not exists)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("dedup: failed to open file %s: %w", path, err)
	}

	ss := &SeenSet{
		seen:     make(map[string]bool),
		file:     f,
		filePath: path,
	}

	// Load existing keys from the file
	if err := ss.loadFromFile(); err != nil {
		f.Close()
		return nil, fmt.Errorf("dedup: failed to load from file %s: %w", path, err)
	}

	return ss, nil
}

// loadFromFile reads all lines from the file and populates the in-memory map.
func (ss *SeenSet) loadFromFile() error {
	// Seek to beginning to read all existing keys
	if _, err := ss.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	scanner := bufio.NewScanner(ss.file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ss.seen[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Seek back to end for appending
	if _, err := ss.file.Seek(0, 2); err != nil {
		return fmt.Errorf("seek to end: %w", err)
	}

	return nil
}

// Seen checks whether a key has already been added to the set.
// Returns true if the key is known, false otherwise.
func (ss *SeenSet) Seen(key string) bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.seen[key]
}

// Add inserts a key into the set. It immediately writes the key to the
// backing file (with a trailing newline) and adds it to the in-memory map.
// If the key is already present, Add is a no-op and returns nil.
func (ss *SeenSet) Add(key string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Already seen — skip
	if ss.seen[key] {
		return nil
	}

	// Write to file first for durability
	if _, err := fmt.Fprintln(ss.file, key); err != nil {
		return fmt.Errorf("dedup: failed to write key to file: %w", err)
	}

	// Sync to disk for immediate durability
	if err := ss.file.Sync(); err != nil {
		return fmt.Errorf("dedup: failed to sync file: %w", err)
	}

	// Update in-memory map
	ss.seen[key] = true
	return nil
}

// Close flushes and closes the backing file. The SeenSet should not be
// used after Close is called.
func (ss *SeenSet) Close() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.file != nil {
		err := ss.file.Close()
		ss.file = nil
		if err != nil {
			return fmt.Errorf("dedup: failed to close file: %w", err)
		}
	}
	return nil
}

// Size returns the number of keys currently in the set.
func (ss *SeenSet) Size() int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return len(ss.seen)
}
