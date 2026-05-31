package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	ai21Keyword1 = []byte("AI21-")
	ai21Re       = regexp.MustCompile(`AI21-[A-Za-z0-9]{30,}`)
)

// AI21Detector detects AI21 Studio API keys.
type AI21Detector struct {
	client *http.Client
}

// NewAI21 creates a new AI21Detector.
func NewAI21() *AI21Detector {
	return &AI21Detector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with AI21 keys.
func (d *AI21Detector) Keywords() []string {
	return []string{"AI21-"}
}

// Type returns the provider identifier.
func (d *AI21Detector) Type() string {
	return "ai21"
}

// Description returns a human-readable description.
func (d *AI21Detector) Description() string {
	return "AI21 Studio API key detector (AI21-... pattern)"
}

// FromData scans raw data for AI21 keys.
func (d *AI21Detector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+4 < len(data) && string(data[i:i+5]) == "AI21-" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(ai21Re, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "ai21",
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

// Verify checks an AI21 key against the API.
func (d *AI21Detector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "ai21",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ai21.com/studio/v1/models", nil)
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
	DefaultRegistry.Register(NewAI21())
}
