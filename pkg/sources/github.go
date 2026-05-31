package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHubClient implements the Source interface for GitHub Code Search.
type GitHubClient struct {
	tokens      []string
	tokenIdx    int
	mu          sync.Mutex
	client      *http.Client
	baseURL     string
}

// NewGitHubClient creates a new GitHub client with the provided tokens.
// Tokens are rotated on rate-limit exhaustion.
func NewGitHubClient(tokens []string) *GitHubClient {
	return &GitHubClient{
		tokens:  tokens,
		tokenIdx: 0,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.github.com",
	}
}

// Name returns "github".
func (g *GitHubClient) Name() string {
	return "github"
}

// Search performs a code search against the GitHub API.
func (g *GitHubClient) Search(ctx context.Context, query string) (<-chan Match, <-chan error) {
	matchCh := make(chan Match, 50)
	errCh := make(chan error, 1)

	go func() {
		defer close(matchCh)
		defer close(errCh)

		g.searchCode(ctx, query, matchCh, errCh)
	}()

	return matchCh, errCh
}

// nextToken returns the current token and advances the rotation.
func (g *GitHubClient) nextToken() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	token := g.tokens[g.tokenIdx]
	g.tokenIdx = (g.tokenIdx + 1) % len(g.tokens)
	return token
}

// currentToken returns the current token without advancing.
func (g *GitHubClient) currentToken() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tokens[g.tokenIdx]
}

// rotateToken advances to the next token (used on rate limit).
func (g *GitHubClient) rotateToken() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tokenIdx = (g.tokenIdx + 1) % len(g.tokens)
}

func (g *GitHubClient) searchCode(ctx context.Context, query string, matchCh chan<- Match, errCh chan<- error) {
	if len(g.tokens) == 0 {
		errCh <- fmt.Errorf("github: no tokens configured")
		return
	}

	page := 1
	maxEmptyPages := 3 // safety against infinite loops
	emptyPages := 0

	for {
		select {
		case <-ctx.Done():
			if ctx.Err() != nil {
				errCh <- ctx.Err()
			}
			return
		default:
		}

		results, nextPage, err := g.fetchPage(ctx, query, page)
		if err != nil {
			errCh <- err
			return
		}

		if len(results) == 0 {
			emptyPages++
			if emptyPages >= maxEmptyPages {
				log.Printf("github: no more results after page %d, stopping", page)
				return
			}
		} else {
			emptyPages = 0
			log.Printf("github: page %d returned %d results", page, len(results))
		}

		for _, item := range results {
			select {
			case <-ctx.Done():
				return
			case matchCh <- Match{
				Source: "github",
				Repo:   item.Repository.FullName,
				Path:   item.Path,
				RawURL: item.HTMLURL,
			}:
			}
		}

		if nextPage == 0 {
			return
		}
		page = nextPage
	}
}

// ghSearchResponse is the GitHub search API response.
type ghSearchResponse struct {
	TotalCount        int  `json:"total_count"`
	IncompleteResults bool `json:"incomplete_results"`
	Items             []ghCodeItem `json:"items"`
}

type ghCodeItem struct {
	Name       string       `json:"name"`
	Path       string       `json:"path"`
	SHA        string       `json:"sha"`
	URL        string       `json:"url"`
	GitURL     string       `json:"git_url"`
	HTMLURL    string       `json:"html_url"`
	Repository ghRepository `json:"repository"`
}

type ghRepository struct {
	ID       int    `json:"id"`
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
}

// fetchPage fetches a single page of GitHub code search results.
// Returns results, next page number (0 if no next), and error.
func (g *GitHubClient) fetchPage(ctx context.Context, query string, page int) ([]ghCodeItem, int, error) {
	u := fmt.Sprintf("%s/search/code?q=%s&per_page=100&page=%d",
		g.baseURL, url.QueryEscape(query), page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("github: create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	token := g.nextToken()
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("github: http get: %w", err)
	}
	defer resp.Body.Close()

	// Check rate limit.
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	if remaining != "" {
		if rem, parseErr := strconv.Atoi(remaining); parseErr == nil && rem < 5 {
			// Rate limit nearly exhausted. Sleep until reset and rotate token.
			resetStr := resp.Header.Get("X-RateLimit-Reset")
			if resetStr != "" {
				if resetUnix, parseErr := strconv.ParseInt(resetStr, 10, 64); parseErr == nil {
					resetTime := time.Unix(resetUnix, 0)
					wait := time.Until(resetTime) + time.Second
					if wait > 0 && wait < 15*time.Minute {
						g.rotateToken()
						select {
						case <-ctx.Done():
							return nil, 0, ctx.Err()
						case <-time.After(wait):
						}
						// Retry with rotated token.
						return g.fetchPage(ctx, query, page)
					}
				}
			}
			// If we can't determine reset time, just rotate.
			g.rotateToken()
			return g.fetchPage(ctx, query, page)
		}
	}

	if resp.StatusCode == http.StatusForbidden && remaining == "0" {
		// Rate limited. Rotate token and retry.
		g.rotateToken()
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(10 * time.Second):
		}
		return g.fetchPage(ctx, query, page)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// Bad token. Rotate and retry.
		g.rotateToken()
		return g.fetchPage(ctx, query, page)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("github: status %d: %s", resp.StatusCode, string(body))
	}

	var result ghSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("github: decode: %w", err)
	}

	nextPage := parseNextPage(resp.Header.Get("Link"))

	return result.Items, nextPage, nil
}

// parseNextPage extracts the next page number from the Link header.
// Example: <https://api.github.com/search/code?q=QUERY&page=2>; rel="next"
func parseNextPage(link string) int {
	if link == "" {
		return 0
	}
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				u, err := url.Parse(part[start+1 : end])
				if err != nil {
					return 0
				}
				pageStr := u.Query().Get("page")
				if page, err := strconv.Atoi(pageStr); err == nil {
					return page
				}
			}
		}
	}
	return 0
}

// FetchRawContent fetches raw file content from GitHub.
func (g *GitHubClient) FetchRawContent(ctx context.Context, repoFullName, path string) ([]byte, error) {
	// URL-encode path segments (handle #, spaces, etc.)
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	encodedPath := strings.Join(parts, "/")

	u := fmt.Sprintf("%s/repos/%s/contents/%s", g.baseURL, repoFullName, encodedPath)

	token := g.currentToken()
	maxRetries := len(g.tokens)
	if maxRetries == 0 {
		maxRetries = 1
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, err
		}

		// Check rate limit.
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if rem, parseErr := strconv.Atoi(remaining); parseErr == nil && rem < 5 {
			resp.Body.Close()
			g.rotateToken()
			token = g.currentToken()
			continue
		}

		if resp.StatusCode == http.StatusForbidden {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if strings.Contains(string(body), "rate limit") {
				g.rotateToken()
				token = g.currentToken()
				continue
			}
			return nil, fmt.Errorf("github: forbidden: %s", string(body))
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, fmt.Errorf("github: file not found: %s/%s", repoFullName, path)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("github: raw fetch status %d for %s/%s", resp.StatusCode, repoFullName, path)
		}

		defer resp.Body.Close()

		// Try as file first. If it's an array, it's a directory.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB cap
		if err != nil {
			return nil, fmt.Errorf("github: read body: %w", err)
		}

		// Check if it's a directory listing (JSON array)
		if len(body) > 0 && body[0] == '[' {
			return nil, fmt.Errorf("github: is a directory, not a file: %s/%s", repoFullName, path)
		}

		var ghContent struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			Size     int    `json:"size"`
		}
		if err := json.Unmarshal(body, &ghContent); err != nil {
			return nil, fmt.Errorf("github: decode content: %w", err)
		}

		if ghContent.Encoding != "base64" {
			return nil, fmt.Errorf("github: unexpected encoding: %s", ghContent.Encoding)
		}

		decoded, err := base64.StdEncoding.DecodeString(
			strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == ' ' {
					return -1
				}
				return r
			}, ghContent.Content),
		)
		if err != nil {
			return nil, fmt.Errorf("github: base64 decode: %w", err)
		}

		return decoded, nil
	}

	return nil, fmt.Errorf("github: all tokens exhausted for %s/%s", repoFullName, path)
}
