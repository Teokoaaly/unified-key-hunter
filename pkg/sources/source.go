package sources

import "context"

// Match represents a single match from a source.
type Match struct {
	Source  string `json:"source"`
	Query   string `json:"query"`
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	Line    string `json:"line"`
	RawURL  string `json:"raw_url"`
	Commit  string `json:"commit"`
	Content []byte `json:"content"`
}

// Source defines the interface for key-hunting sources.
type Source interface {
	// Name returns the source identifier (e.g., "sourcegraph", "github").
	Name() string

	// Search performs a search with the given query and returns channels
	// of matches and errors. Both channels are closed when the search
	// is complete or the context is cancelled.
	Search(ctx context.Context, query string) (<-chan Match, <-chan error)
}
