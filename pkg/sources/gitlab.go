package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// GitLabClient implements the Source interface for GitLab Search (blobs).
type GitLabClient struct {
	token   string
	client  *http.Client
	baseURL string
}

// NewGitLabClient creates a new GitLab client with the provided token.
// The token should be a GitLab Personal Access Token or Project Access Token.
func NewGitLabClient(token string) *GitLabClient {
	return &GitLabClient{
		token: token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://gitlab.com",
	}
}

// Name returns "gitlab".
func (g *GitLabClient) Name() string {
	return "gitlab"
}

// Search performs a blob search against the GitLab API.
// It respects RateLimit-Remaining and RateLimit-Reset headers.
// Pagination is driven by the X-Next-Page header.
func (g *GitLabClient) Search(ctx context.Context, query string) (<-chan Match, <-chan error) {
	matchCh := make(chan Match, 50)
	errCh := make(chan error, 1)

	go func() {
		defer close(matchCh)
		defer close(errCh)

		g.searchBlobs(ctx, query, matchCh, errCh)
	}()

	return matchCh, errCh
}

func (g *GitLabClient) searchBlobs(ctx context.Context, query string, matchCh chan<- Match, errCh chan<- error) {
	if g.token == "" {
		errCh <- fmt.Errorf("gitlab: no token configured (set GITLAB_TOKEN env var or pass via flag)")
		return
	}

	page := 1
	maxEmptyPages := 3
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
				return
			}
		} else {
			emptyPages = 0
		}

		for _, item := range results {
			select {
			case <-ctx.Done():
				return
			case matchCh <- Match{
				Source: "gitlab",
				Repo:   item.ProjectID,
				Path:   item.Path,
				RawURL: item.Filename,
			}:
			}
		}

		if nextPage == 0 {
			return
		}
		page = nextPage
	}
}

// glSearchResponse represents the GitLab search API response.
type glSearchResponse struct {
	ID     int          `json:"id"`
	Basename string     `json:"basename"`
	Data   string       `json:"data"`
	Path   string       `json:"path"`
	Filename string     `json:"filename"`
	ProjectID string    `json:"project_id"`
	Ref    string       `json:"ref"`
	Startline int       `json:"startline"`
}

// fetchPage fetches a single page of GitLab blob search results.
// Returns results, next page number (0 if no next), and error.
func (g *GitLabClient) fetchPage(ctx context.Context, query string, page int) ([]glSearchResponse, int, error) {
	u := fmt.Sprintf("%s/api/v4/search?scope=blobs&search=%s&per_page=100&page=%d",
		g.baseURL, url.QueryEscape(query), page)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("gitlab: create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("gitlab: http get: %w", err)
	}
	defer resp.Body.Close()

	// Check rate limit.
	remaining := resp.Header.Get("RateLimit-Remaining")
	if remaining != "" {
		if rem, parseErr := strconv.Atoi(remaining); parseErr == nil && rem < 5 {
			resetStr := resp.Header.Get("RateLimit-Reset")
			if resetStr != "" {
				if resetUnix, parseErr := strconv.ParseInt(resetStr, 10, 64); parseErr == nil {
					resetTime := time.Unix(resetUnix, 0)
					wait := time.Until(resetTime) + time.Second
					if wait > 0 && wait < 15*time.Minute {
						select {
						case <-ctx.Done():
							return nil, 0, ctx.Err()
						case <-time.After(wait):
						}
						return g.fetchPage(ctx, query, page)
					}
				}
			}
			// If we can't determine reset time, just wait a bit.
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(10 * time.Second):
			}
			return g.fetchPage(ctx, query, page)
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Retry after a cooldown.
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(10 * time.Second):
		}
		return g.fetchPage(ctx, query, page)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, 0, fmt.Errorf("gitlab: unauthorized (invalid token)")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("gitlab: status %d: %s", resp.StatusCode, string(body))
	}

	var results []glSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, 0, fmt.Errorf("gitlab: decode: %w", err)
	}

	// Parse X-Next-Page header for pagination.
	nextPage := 0
	nextPageStr := resp.Header.Get("X-Next-Page")
	if nextPageStr != "" {
		if np, err := strconv.Atoi(nextPageStr); err == nil {
			nextPage = np
		}
	}

	return results, nextPage, nil
}

// glFileResponse represents the GitLab repository file API response.
type glFileResponse struct {
	FileName     string `json:"file_name"`
	FilePath     string `json:"file_path"`
	Size         int    `json:"size"`
	Encoding     string `json:"encoding"`
	Content      string `json:"content"`
	BlobID       string `json:"blob_id"`
	Ref          string `json:"ref"`
}

// FetchRawContent fetches raw file content from GitLab.
// projectID can be a numeric project ID (e.g., "12345678") or a URL-encoded
// full path (e.g., "group%2Fproject").
func (g *GitLabClient) FetchRawContent(ctx context.Context, projectID, filePath string) ([]byte, error) {
	// URL-encode the file path for the API.
	encodedPath := url.PathEscape(filePath)
	// GitLab API encodes slashes as %2F.
	u := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=main",
		g.baseURL, projectID, encodedPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("gitlab: create request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab: http get: %w", err)
	}
	defer resp.Body.Close()

	// Check rate limit.
	remaining := resp.Header.Get("RateLimit-Remaining")
	if remaining != "" {
		if rem, parseErr := strconv.Atoi(remaining); parseErr == nil && rem < 5 {
			resetStr := resp.Header.Get("RateLimit-Reset")
			if resetStr != "" {
				if resetUnix, parseErr := strconv.ParseInt(resetStr, 10, 64); parseErr == nil {
					resetTime := time.Unix(resetUnix, 0)
					wait := time.Until(resetTime) + time.Second
					if wait > 0 && wait < 15*time.Minute {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(wait):
						}
					}
				}
			}
		}
		return g.FetchRawContent(ctx, projectID, filePath)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab: raw fetch status %d for project=%s, file=%s",
			resp.StatusCode, projectID, filePath)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
}
