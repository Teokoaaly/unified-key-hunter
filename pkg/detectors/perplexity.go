package detectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	perplexityKeyword1 = []byte("pplx-")
	perplexityRe       = regexp.MustCompile(`pplx-[A-Za-z0-9]{30,}`)
)

// PerplexityDetector detects Perplexity API keys.
type PerplexityDetector struct {
	client *http.Client
}

// NewPerplexity creates a new PerplexityDetector.
func NewPerplexity() *PerplexityDetector {
	return &PerplexityDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Perplexity keys.
func (d *PerplexityDetector) Keywords() []string {
	return []string{"pplx-"}
}

// Type returns the provider identifier.
func (d *PerplexityDetector) Type() string {
	return "perplexity"
}

// Description returns a human-readable description.
func (d *PerplexityDetector) Description() string {
	return "Perplexity API key detector (pplx-... pattern)"
}

// FromData scans raw data for Perplexity keys.
func (d *PerplexityDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+4 < len(data) && string(data[i:i+5]) == "pplx-" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(perplexityRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "perplexity",
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

// Verify checks a Perplexity key against the API.
func (d *PerplexityDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "perplexity",
		Redacted: RedactKey(key),
	}

	payload := map[string]interface{}{
		"model":      "sonar",
		"max_tokens": 1,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return r, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.perplexity.ai/chat/completions", bytes.NewReader(body))
	if err != nil {
		return r, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

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
	DefaultRegistry.Register(NewPerplexity())
}
