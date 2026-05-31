package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	replicateKeyword1 = []byte("r8_")
	replicateRe       = regexp.MustCompile(`r8_[A-Za-z0-9]{30,}`)
)

// ReplicateDetector detects Replicate API keys.
type ReplicateDetector struct {
	client *http.Client
}

// NewReplicate creates a new ReplicateDetector.
func NewReplicate() *ReplicateDetector {
	return &ReplicateDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Replicate keys.
func (d *ReplicateDetector) Keywords() []string {
	return []string{"r8_"}
}

// Type returns the provider identifier.
func (d *ReplicateDetector) Type() string {
	return "replicate"
}

// Description returns a human-readable description.
func (d *ReplicateDetector) Description() string {
	return "Replicate API key detector (r8_... pattern)"
}

// FromData scans raw data for Replicate keys.
func (d *ReplicateDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+2 < len(data) && string(data[i:i+3]) == "r8_" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(replicateRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "replicate",
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

// Verify checks a Replicate key against the API.
func (d *ReplicateDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "replicate",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.replicate.com/v1/models", nil)
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
	DefaultRegistry.Register(NewReplicate())
}
