package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	fireworksKeyword1 = []byte("fw_")
	fireworksRe       = regexp.MustCompile(`fw_[A-Za-z0-9]{30,}`)
)

// FireworksDetector detects Fireworks AI API keys.
type FireworksDetector struct {
	client *http.Client
}

// NewFireworks creates a new FireworksDetector.
func NewFireworks() *FireworksDetector {
	return &FireworksDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Fireworks keys.
func (d *FireworksDetector) Keywords() []string {
	return []string{"fw_"}
}

// Type returns the provider identifier.
func (d *FireworksDetector) Type() string {
	return "fireworks"
}

// Description returns a human-readable description.
func (d *FireworksDetector) Description() string {
	return "Fireworks AI API key detector (fw_... pattern)"
}

// FromData scans raw data for Fireworks keys.
func (d *FireworksDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+2 < len(data) && string(data[i:i+3]) == "fw_" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(fireworksRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "fireworks",
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

// Verify checks a Fireworks key against the API.
func (d *FireworksDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "fireworks",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.fireworks.ai/inference/v1/models", nil)
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
	DefaultRegistry.Register(NewFireworks())
}
