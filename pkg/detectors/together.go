package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	togetherKeyword1 = []byte("together_")
	togetherKeyword2 = []byte("tgr_")
	togetherRe       = regexp.MustCompile(`(together_|tgr_)[A-Za-z0-9]{20,}`)
)

// TogetherDetector detects Together AI API keys.
type TogetherDetector struct {
	client *http.Client
}

// NewTogether creates a new TogetherDetector.
func NewTogether() *TogetherDetector {
	return &TogetherDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Together keys.
func (d *TogetherDetector) Keywords() []string {
	return []string{"together_", "tgr_"}
}

// Type returns the provider identifier.
func (d *TogetherDetector) Type() string {
	return "together"
}

// Description returns a human-readable description.
func (d *TogetherDetector) Description() string {
	return "Together AI API key detector (together_/tgr_... pattern)"
}

// FromData scans raw data for Together keys.
func (d *TogetherDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasTogether := false
	hasTgr := false
	for i := 0; i < len(data); i++ {
		if !hasTogether && i+8 < len(data) && string(data[i:i+9]) == "together_" {
			hasTogether = true
		}
		if !hasTgr && i+3 < len(data) && string(data[i:i+4]) == "tgr_" {
			hasTgr = true
		}
		if hasTogether || hasTgr {
			break
		}
	}
	if !hasTogether && !hasTgr {
		return nil, nil
	}

	matches := extractMatches(togetherRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "together",
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

// Verify checks a Together key against the API.
func (d *TogetherDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "together",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.together.xyz/v1/models", nil)
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
	DefaultRegistry.Register(NewTogether())
}
