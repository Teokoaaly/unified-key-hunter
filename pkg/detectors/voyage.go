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
	voyageKeyword1 = []byte("vo-")
	voyageKeyword2 = []byte("vs-")
	voyageRe       = regexp.MustCompile(`(vo-|vs-)[A-Za-z0-9]{30,}`)
)

// VoyageDetector detects Voyage AI API keys.
type VoyageDetector struct {
	client *http.Client
}

// NewVoyage creates a new VoyageDetector.
func NewVoyage() *VoyageDetector {
	return &VoyageDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Voyage keys.
func (d *VoyageDetector) Keywords() []string {
	return []string{"vo-", "vs-"}
}

// Type returns the provider identifier.
func (d *VoyageDetector) Type() string {
	return "voyage"
}

// Description returns a human-readable description.
func (d *VoyageDetector) Description() string {
	return "Voyage AI API key detector (vo-/vs-... pattern)"
}

// FromData scans raw data for Voyage keys.
func (d *VoyageDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasVo := false
	hasVs := false
	for i := 0; i < len(data); i++ {
		if !hasVo && i+2 < len(data) && data[i] == 'v' && data[i+1] == 'o' && data[i+2] == '-' {
			hasVo = true
		}
		if !hasVs && i+2 < len(data) && data[i] == 'v' && data[i+1] == 's' && data[i+2] == '-' {
			hasVs = true
		}
		if hasVo || hasVs {
			break
		}
	}
	if !hasVo && !hasVs {
		return nil, nil
	}

	matches := extractMatches(voyageRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "voyage",
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

// Verify checks a Voyage key against the API.
func (d *VoyageDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "voyage",
		Redacted: RedactKey(key),
	}

	payload := map[string]interface{}{
		"model": "voyage-3-lite",
		"input": []string{"hi"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return r, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.voyageai.com/v1/embeddings", bytes.NewReader(body))
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
	DefaultRegistry.Register(NewVoyage())
}
