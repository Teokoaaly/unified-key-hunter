package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	huggingfaceKeyword1 = []byte("hf_")
	huggingfaceRe       = regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`)
)

// HuggingFaceDetector detects Hugging Face API keys.
type HuggingFaceDetector struct {
	client *http.Client
}

// NewHuggingFace creates a new HuggingFaceDetector.
func NewHuggingFace() *HuggingFaceDetector {
	return &HuggingFaceDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with Hugging Face keys.
func (d *HuggingFaceDetector) Keywords() []string {
	return []string{"hf_"}
}

// Type returns the provider identifier.
func (d *HuggingFaceDetector) Type() string {
	return "huggingface"
}

// Description returns a human-readable description.
func (d *HuggingFaceDetector) Description() string {
	return "Hugging Face API key detector (hf_... pattern)"
}

// FromData scans raw data for Hugging Face keys.
func (d *HuggingFaceDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+2 < len(data) && string(data[i:i+3]) == "hf_" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(huggingfaceRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "huggingface",
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

// Verify checks a Hugging Face key against the API.
func (d *HuggingFaceDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "huggingface",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://huggingface.co/api/whoami", nil)
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
	DefaultRegistry.Register(NewHuggingFace())
}
