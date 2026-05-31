package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	cohereKeyword1 = []byte("cohere")
	cohereKeyword2 = []byte("sk-cohere-")
	cohereRe       = regexp.MustCompile(`sk-cohere-[A-Za-z0-9]{32,}|[A-Za-z0-9]{40}`)
)

// CohereDetector detects Cohere API keys.
type CohereDetector struct {
	client *http.Client
}

// NewCohere creates a new CohereDetector.
func NewCohere() *CohereDetector {
	return &CohereDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Cohere keys.
func (d *CohereDetector) Keywords() []string {
	return []string{"cohere", "sk-cohere-"}
}

// Type returns the provider identifier.
func (d *CohereDetector) Type() string {
	return "cohere"
}

// Description returns a human-readable description.
func (d *CohereDetector) Description() string {
	return "Cohere API key detector (40 chars or sk-cohere-... pattern)"
}

// FromData scans raw data for Cohere keys.
func (d *CohereDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasKeyword := false
	for i := 0; i < len(data); i++ {
		if !hasKeyword && i+5 < len(data) && string(data[i:i+6]) == "cohere" {
			hasKeyword = true
			break
		}
	}
	if !hasKeyword {
		return nil, nil
	}

	matches := extractMatches(cohereRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "cohere",
			Raw:      m,
			Redacted: RedactKey(key),
			Verified: false,
			Status:   "UNVERIFIED",
		}
		if verify {
			vr, err := d.Verify(ctx, key)
			if err != nil {
				r.Status = "ERROR"
			} else {
				r = vr
				r.Raw = m
			}
		}
		results = append(results, r)
	}
	return deduplicateResults(results), nil
}

// Verify checks a Cohere key against the API.
func (d *CohereDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "cohere",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cohere.com/v1/models", nil)
	if err != nil {
		return r, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := d.client.Do(req)
	if err != nil {
		r.Status = "ERROR"
		r.Verified = false
		return r, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		r.Status = "LIVE"
		r.Verified = true
	case http.StatusUnauthorized, http.StatusForbidden:
		r.Status = "DEAD"
		r.Verified = false
	case http.StatusTooManyRequests:
		r.Status = "WARM"
		r.Verified = true
	default:
		r.Status = "DEAD"
		r.Verified = false
	}

	return r, nil
}

func init() {
	DefaultRegistry.Register(NewCohere())
}
