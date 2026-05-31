package detectors

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Result holds the detection result for a single key.
// Fields prefixed with Detector_ are used by the detector subsystem (FromData/Verify).
// Fields without prefix are used by the storage/engine subsystem.
type Result struct {
	// --- Detector-side fields (used by openai/anthropic/deepseek detectors) ---
	Provider     string   `json:"provider"`      // e.g. "openai", "anthropic"
	Raw          []byte   `json:"raw"`            // raw key bytes from source data
	Redacted     string   `json:"redacted"`       // redacted display version
	Verified     bool     `json:"verified"`       // whether key was verified via API
	BalanceUSD   float64  `json:"balance_usd"`    // balance in USD (from verify)
	BalanceCNY   float64  `json:"balance_cny"`    // balance in CNY (from verify)
	Capabilities []string `json:"capabilities"`   // provider-specific capabilities

	// --- Storage/engine-side fields (used by storage.KeysDB) ---
	Key       string    `json:"key"`       // the raw key string (primary key)
	Type      string    `json:"type"`      // provider type (mirrors Provider for storage)
	Balance   float64   `json:"balance"`   // generic balance field (used by storage)
	Source    string    `json:"source"`    // source platform (github, sourcegraph)
	Path      string    `json:"path"`      // file path where key was found
	Repo      string    `json:"repo"`      // repository where key was found
	RawURL    string    `json:"raw_url"`   // URL to raw file
	Line      string    `json:"line"`      // matching line content
	Status    string    `json:"status"`    // "verified"|"unverified"|"empty"|"error" (storage)
	Timestamp time.Time `json:"timestamp"` // detection timestamp
}

// Status constants for storage compatibility.
const (
	StatusVerified   = "verified"
	StatusUnverified = "unverified"
	StatusEmpty      = "empty"
	StatusError      = "error"
)

// HasBalance reports whether the result has a positive balance.
func (r *Result) HasBalance() bool {
	return r.Balance > 0
}

// IsBetterStatusThan reports whether this result's status is "better" than another.
// verified > unverified > empty > error
func (r *Result) IsBetterStatusThan(other *Result) bool {
	rank := map[string]int{
		StatusVerified:   4,
		StatusUnverified: 3,
		StatusEmpty:      2,
		StatusError:      1,
	}
	return rank[r.Status] > rank[other.Status]
}

// Detector is the interface every provider detector must implement.
type Detector interface {
	// Keywords returns the list of keywords associated with this detector
	// (e.g., "sk-", "deepseek", "openai"). Used for scanning data.
	Keywords() []string

	// FromData extracts key candidates from raw data. If verify is true,
	// the detector should also validate each candidate.
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)

	// Type returns a short, unique provider identifier (e.g., "deepseek", "openrouter").
	Type() string

	// Description returns a human-readable description of the detector.
	Description() string

	// Verify tests whether a given key is valid and returns its status.
	Verify(ctx context.Context, key string) (Result, error)
}

// Registry holds all registered detectors and provides lookup methods.
type Registry struct {
	mu        sync.RWMutex
	detectors map[string]Detector // provider type -> Detector
}

// NewRegistry creates and returns a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
	}
}

// Register adds a detector to the registry. It panics if a detector
// with the same Type() is already registered.
func (r *Registry) Register(d Detector) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := d.Type()
	if _, exists := r.detectors[name]; exists {
		panic(fmt.Sprintf("detectors: duplicate registration for %q", name))
	}
	r.detectors[name] = d
}

// Get retrieves a detector by provider type string.
// Returns the detector and true if found, nil and false otherwise.
func (r *Registry) Get(provider string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	d, ok := r.detectors[provider]
	return d, ok
}

// AllKeywords collects and returns all keywords from every registered detector.
// Keywords are deduplicated.
func (r *Registry) AllKeywords() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var keywords []string
	for _, d := range r.detectors {
		for _, kw := range d.Keywords() {
			kw = strings.ToLower(strings.TrimSpace(kw))
			if kw == "" || seen[kw] {
				continue
			}
			seen[kw] = true
			keywords = append(keywords, kw)
		}
	}
	return keywords
}

// DetectProvider attempts to guess the provider for a given key string
// by checking registered detectors' keywords against the key prefix.
// Returns the provider type string if a match is found, empty string otherwise.
func (r *Registry) DetectProvider(key string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lower := strings.ToLower(strings.TrimSpace(key))

	for _, d := range r.detectors {
		for _, kw := range d.Keywords() {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return d.Type()
			}
		}
	}
	return ""
}

// DefaultRegistry is the global registry used by init() auto-registration.
var DefaultRegistry = NewRegistry()

// RedactKey truncates a key for safe display, showing first 4 and last 3 characters.
func RedactKey(key string) string {
	if len(key) <= 1 {
		return key
	}
	if len(key) <= 5 {
		return key[:1] + strings.Repeat("*", len(key)-1)
	}
	return key[:4] + strings.Repeat("*", len(key)-7) + key[len(key)-3:]
}

// extractMatches extracts all unique matching substrings using the given regex.
func extractMatches(re *regexp.Regexp, data []byte) [][]byte {
	matches := re.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	out := make([][]byte, 0, len(matches))
	for _, m := range matches {
		s := string(m)
		if !seen[s] {
			seen[s] = true
			out = append(out, m)
		}
	}
	return out
}

// deduplicateResults removes duplicate keys from a slice of Results.
func deduplicateResults(results []Result) []Result {
	seen := make(map[string]bool)
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if !seen[r.Key] {
			seen[r.Key] = true
			out = append(out, r)
		}
	}
	return out
}
