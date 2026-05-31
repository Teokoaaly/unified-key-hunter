package engine

import (
	"sync"
)

// SeenSet tracks unique keys already seen to avoid duplicate processing.
type SeenSet struct {
	mu   sync.RWMutex
	keys map[string]bool
}

// NewSeenSet creates a new empty SeenSet.
func NewSeenSet() *SeenSet {
	return &SeenSet{
		keys: make(map[string]bool),
	}
}

// Add marks a key as seen. Returns true if the key was new.
func (s *SeenSet) Add(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys[key] {
		return false
	}
	s.keys[key] = true
	return true
}

// Has reports whether a key has been seen.
func (s *SeenSet) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[key]
}

// Count returns the number of unique keys seen.
func (s *SeenSet) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}
