package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	groqKeyword1 = []byte("gsk_")
	groqRe       = regexp.MustCompile(`gsk_[A-Za-z0-9]{26,}`)
)

// GroqDetector detects Groq API keys.
type GroqDetector struct {
	client *http.Client
}

// NewGroq creates a new GroqDetector.
func NewGroq() *GroqDetector {
	return &GroqDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Groq keys.
func (d *GroqDetector) Keywords() []string {
	return []string{"gsk_"}
}

// Type returns the provider identifier.
func (d *GroqDetector) Type() string {
	return "groq"
}

// Description returns a human-readable description.
func (d *GroqDetector) Description() string {
	return "Groq API key detector (gsk_... pattern, 30+ chars)"
}

// FromData scans raw data for Groq keys.
func (d *GroqDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+3 < len(data) && string(data[i:i+4]) == "gsk_" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(groqRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "groq",
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

// Verify checks a Groq key against the API.
func (d *GroqDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "groq",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.groq.com/openai/v1/models", nil)
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
	DefaultRegistry.Register(NewGroq())
}
