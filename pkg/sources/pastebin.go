package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// PastebinClient implements the Source interface for Pastebin scraping (PRO mode).
// It polls scrape.pastebin.com every 60 seconds for new pastes.
// No authentication is required for PRO scraping — the user's IP must be
// whitelisted in their Pastebin PRO account.
type PastebinClient struct {
	client     *http.Client
	knownKeys  map[string]struct{} // already-seen paste keys
	mu         sync.Mutex
	baseURL    string
}

// NewPastebinClient creates a new Pastebin scraping client.
func NewPastebinClient() *PastebinClient {
	return &PastebinClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		knownKeys: make(map[string]struct{}),
		baseURL:   "https://scrape.pastebin.com",
	}
}

// Name returns "pastebin".
func (p *PastebinClient) Name() string {
	return "pastebin"
}

// Search starts polling Pastebin's scraping API for new pastes.
// It returns channels for matches and errors. The channels are closed when
// the context is cancelled. New pastes are emitted as Match values with
// populated Content field (no separate fetch needed).
func (p *PastebinClient) Search(ctx context.Context, query string) (<-chan Match, <-chan error) {
	matchCh := make(chan Match, 50)
	errCh := make(chan error, 1)

	go func() {
		defer close(matchCh)
		defer close(errCh)

		p.poll(ctx, query, matchCh, errCh)
	}()

	return matchCh, errCh
}

func (p *PastebinClient) poll(ctx context.Context, query string, matchCh chan<- Match, errCh chan<- error) {
	// Do an initial fetch immediately.
	if err := p.fetchAndEmit(ctx, query, matchCh); err != nil {
		errCh <- err
		return
	}

	// Then poll every 60 seconds.
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				errCh <- ctx.Err()
			}
			return
		case <-ticker.C:
			if err := p.fetchAndEmit(ctx, query, matchCh); err != nil {
				// Log errors but keep polling; don't stop the loop.
				select {
				case errCh <- err:
				default:
				}
			}
		}
	}
}

// pastebinItem represents a single paste from the scraping list API.
type pastebinItem struct {
	ScrapeURL string `json:"scrape_url"`
	FullURL   string `json:"full_url"`
	Date      string `json:"date"`
	Key       string `json:"key"`
	Size      string `json:"size"`
	Expire    string `json:"expire"`
	Title     string `json:"title"`
	Syntax    string `json:"syntax"`
	User      string `json:"user"`
}

// fetchAndEmit fetches the latest paste list, filters out already-seen pastes,
// fetches content for each new paste, and emits overlaps with query.
func (p *PastebinClient) fetchAndEmit(ctx context.Context, query string, matchCh chan<- Match) error {
	items, err := p.fetchList(ctx)
	if err != nil {
		return fmt.Errorf("pastebin: fetch list: %w", err)
	}

	for _, item := range items {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip already-known pastes.
		if p.isKnown(item.Key) {
			continue
		}
		p.markKnown(item.Key)

		// Fetch raw content for this paste.
		content, err := p.FetchRawContent(ctx, item.Key)
		if err != nil {
			// Silently skip pastes we can't fetch (they might be expired or private).
			continue
		}

		// Simple content check: if the user specified a query, check if it
		// appears in the content (case-insensitive). An empty query matches
		// everything (catching all new pastes).
		if query != "" && !containsFold(string(content), query) {
			continue
		}

		match := Match{
			Source:  "pastebin",
			Query:   query,
			Repo:    item.User, // paste author as "repo" equivalent
			Path:    item.Key,  // paste key as "path"
			Line:    item.Title,
			RawURL:  item.FullURL,
			Content: content,
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case matchCh <- match:
		}
	}

	return nil
}

// fetchList fetches the latest 100 pastes from the scraping API.
func (p *PastebinClient) fetchList(ctx context.Context) ([]pastebinItem, error) {
	u := fmt.Sprintf("%s/api_scraping.php?limit=100", p.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("pastebin: create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pastebin: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("pastebin: access denied (IP %s may not be whitelisted — check your Pastebin PRO scraping settings)", req.RemoteAddr)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("pastebin: status %d: %s", resp.StatusCode, string(body))
	}

	var items []pastebinItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("pastebin: decode list: %w", err)
	}

	return items, nil
}

// FetchRawContent fetches the raw content of a single paste by its key.
func (p *PastebinClient) FetchRawContent(ctx context.Context, key string) ([]byte, error) {
	u := fmt.Sprintf("%s/api_scrape_item.php?i=%s", p.baseURL, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("pastebin: create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pastebin: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pastebin: fetch item %s status %d", key, resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
}

// isKnown checks whether a paste key has already been processed.
func (p *PastebinClient) isKnown(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.knownKeys[key]
	return ok
}

// markKnown records a paste key as processed.
func (p *PastebinClient) markKnown(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.knownKeys[key] = struct{}{}
}

// containsFold does a case-insensitive substring search.
func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	return indexFold(s, substr) >= 0
}

// indexFold returns the byte index of substr in s (case-insensitive) or -1.
// Avoids allocations; operates on raw bytes.
func indexFold(s, substr string) int {
	n := len(substr)
	limit := len(s) - n + 1
	for i := 0; i < limit; i++ {
		j := 0
		for ; j < n; j++ {
			sc := s[i+j]
			su := substr[j]
			// Case-fold only ASCII A-Z/a-z.
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if su >= 'A' && su <= 'Z' {
				su += 32
			}
			if sc != su {
				break
			}
		}
		if j == n {
			return i
		}
	}
	return -1
}
