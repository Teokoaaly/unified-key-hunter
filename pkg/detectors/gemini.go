package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	geminiKeyword1 = []byte("AIzaSy")
	geminiRe       = regexp.MustCompile(`AIzaSy[A-Za-z0-9_-]{27}`)
)

// GeminiDetector detects Google Gemini API keys.
type GeminiDetector struct {
	client *http.Client
}

// NewGemini creates a new GeminiDetector.
func NewGemini() *GeminiDetector {
	return &GeminiDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Gemini keys.
func (d *GeminiDetector) Keywords() []string {
	return []string{"AIzaSy"}
}

// Type returns the provider identifier.
func (d *GeminiDetector) Type() string {
	return "gemini"
}

// Description returns a human-readable description.
func (d *GeminiDetector) Description() string {
	return "Google Gemini API key detector (AIzaSy... pattern, 33 chars)"
}

// FromData scans raw data for Gemini keys.
func (d *GeminiDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+5 < len(data) && string(data[i:i+6]) == "AIzaSy" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(geminiRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "gemini",
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

// Verify checks a Gemini key against the API.
func (d *GeminiDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "gemini",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://generativelanguage.googleapis.com/v1/models?key="+key, nil)
	if err != nil {
		return r, fmt.Errorf("create request: %w", err)
	}

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
	DefaultRegistry.Register(NewGemini())
}
