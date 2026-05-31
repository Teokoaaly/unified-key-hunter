package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	mistralKeyword1 = []byte("mistral")
	mistralRe       = regexp.MustCompile(`[A-Za-z0-9]{32}`)
)

// MistralDetector detects Mistral API keys.
type MistralDetector struct {
	client *http.Client
}

// NewMistral creates a new MistralDetector.
func NewMistral() *MistralDetector {
	return &MistralDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Mistral keys.
func (d *MistralDetector) Keywords() []string {
	return []string{"mistral"}
}

// Type returns the provider identifier.
func (d *MistralDetector) Type() string {
	return "mistral"
}

// Description returns a human-readable description.
func (d *MistralDetector) Description() string {
	return "Mistral API key detector (32 chars, near MISTRAL_API_KEY context)"
}

// FromData scans raw data for Mistral keys.
func (d *MistralDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasKeyword := false
	for i := 0; i < len(data); i++ {
		if !hasKeyword && i+6 < len(data) {
			s := string(data[i : i+7])
			if s == "mistral" || s == "MISTRAL" {
				hasKeyword = true
				break
			}
		}
	}
	if !hasKeyword {
		return nil, nil
	}

	matches := extractMatches(mistralRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "mistral",
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

// Verify checks a Mistral key against the API.
func (d *MistralDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "mistral",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mistral.ai/v1/models", nil)
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
	DefaultRegistry.Register(NewMistral())
}
