package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SourcegraphClient implements the Source interface for Sourcegraph.
type SourcegraphClient struct {
	client     *http.Client
	rateTicker *time.Ticker // 2 req/s = 500ms tick
}

// NewSourcegraphClient creates a new Sourcegraph client.
func NewSourcegraphClient() *SourcegraphClient {
	return &SourcegraphClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		rateTicker: time.NewTicker(500 * time.Millisecond),
	}
}

// Name returns "sourcegraph".
func (s *SourcegraphClient) Name() string {
	return "sourcegraph"
}

// Search performs an SSE search against Sourcegraph's stream API.
func (s *SourcegraphClient) Search(ctx context.Context, query string) (<-chan Match, <-chan error) {
	matchCh := make(chan Match, 50)
	errCh := make(chan error, 1)

	go func() {
		defer close(matchCh)
		defer close(errCh)
		defer s.rateTicker.Stop()

		s.searchStream(ctx, query, matchCh, errCh)
	}()

	return matchCh, errCh
}

// sseMatch is the JSON structure of a single match from the SSE stream.
type sseMatch struct {
	Type         string          `json:"type"`
	Repository   string          `json:"repository"`
	Path         string          `json:"path"`
	Commit       string          `json:"commit"`
	LineMatches  []sseLineMatch  `json:"lineMatches"`
	ChunkMatches []sseChunkMatch `json:"chunkMatches"` // legacy, some older Sourcegraph versions
}

type sseLineMatch struct {
	Line             string `json:"line"`
	LineNumber       int    `json:"lineNumber"`
	OffsetAndLengths [][]int `json:"offsetAndLengths"`
}

type sseChunkMatch struct {
	Content string `json:"content"`
}

func (s *SourcegraphClient) searchStream(ctx context.Context, query string, matchCh chan<- Match, errCh chan<- error) {
	// Build the URL.
	u := fmt.Sprintf("https://sourcegraph.com/.api/search/stream?q=%s&patternType=regexp",
		url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		errCh <- fmt.Errorf("sourcegraph: create request: %w", err)
		return
	}
	req.Header.Set("Accept", "text/event-stream")

	// Rate limit.
	select {
	case <-ctx.Done():
		errCh <- ctx.Err()
		return
	case <-s.rateTicker.C:
	}

	resp, err := s.client.Do(req)
	if err != nil {
		errCh <- fmt.Errorf("sourcegraph: http get: %w", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errCh <- fmt.Errorf("sourcegraph: status %d", resp.StatusCode)
		return
	}

	s.parseSSE(ctx, resp.Body, matchCh, errCh)
}

func (s *SourcegraphClient) parseSSE(ctx context.Context, body io.Reader, matchCh chan<- Match, errCh chan<- error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB buffer

	var currentEvent string
	var dataLines []string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				errCh <- ctx.Err()
			}
			return
		default:
		}

		line := scanner.Text()

		if line == "" {
			// Empty line signals end of an event. Process it.
			if currentEvent == "done" {
				return
			}
			if currentEvent == "matches" && len(dataLines) > 0 {
				s.processMatches(dataLines, matchCh)
			}
			currentEvent = ""
			dataLines = dataLines[:0]
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(line[5:])
			if data != "" {
				dataLines = append(dataLines, data)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		errCh <- fmt.Errorf("sourcegraph: scan error: %w", err)
	}
}

func (s *SourcegraphClient) processMatches(dataLines []string, matchCh chan<- Match) {
	// dataLines may contain multiple JSON arrays concatenated.
	for _, data := range dataLines {
		var matches []sseMatch
		if err := json.Unmarshal([]byte(data), &matches); err != nil {
			// Try as a single object.
			var m sseMatch
			if err2 := json.Unmarshal([]byte(data), &m); err2 == nil {
				matches = []sseMatch{m}
			} else {
				continue
			}
		}

		for _, m := range matches {
			rawURL := s.buildRawURL(m.Repository, m.Path, m.Commit)
			line := ""

			// Extract line content from lineMatches (current Sourcegraph API)
			if m.Type == "content" && len(m.LineMatches) > 0 {
				line = m.LineMatches[0].Line
			}
			// Fallback: chunkMatches (older Sourcegraph versions)
			if line == "" && len(m.ChunkMatches) > 0 {
				line = m.ChunkMatches[0].Content
			}

			match := Match{
				Source: "sourcegraph",
				Repo:   m.Repository,
				Path:   m.Path,
				Line:   line,
				RawURL: rawURL,
				Commit: m.Commit,
			}

			select {
			case matchCh <- match:
			default:
				// Channel full, drop match.
			}
		}
	}
}

// buildRawURL converts a Sourcegraph repository path to a raw GitHub URL.
// Sourcegraph repos are like "github.com/owner/repo".
// Uses the commit SHA provided by Sourcegraph for exact version pinning.
func (s *SourcegraphClient) buildRawURL(repo, path, commit string) string {
	repo = strings.TrimPrefix(repo, "github.com/")
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	ref := commit
	if ref == "" {
		ref = "main"
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		parts[0], parts[1], ref, path)
}

// FetchRawContent fetches the raw content for a match via GitHub raw URLs.
func (s *SourcegraphClient) FetchRawContent(ctx context.Context, rawURL string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.rateTicker.C:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sourcegraph: raw fetch status %d for %s", resp.StatusCode, rawURL)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
}
