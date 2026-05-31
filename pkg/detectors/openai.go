package detectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	openaiKeyword1 = []byte("sk-")
	openaiKeyword2 = []byte("T3BlbkFJ")
	openaiRe       = regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9]{20,}`)
)

// OpenAIDetector detects OpenAI API keys.
type OpenAIDetector struct {
	client *http.Client
}

// NewOpenAI creates a new OpenAIDetector.
func NewOpenAI() *OpenAIDetector {
	return &OpenAIDetector{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Keywords returns keywords associated with OpenAI keys.
func (d *OpenAIDetector) Keywords() []string {
	return []string{"sk-", "T3BlbkFJ"}
}

// Type returns the provider identifier.
func (d *OpenAIDetector) Type() string {
	return "openai"
}

// Description returns a human-readable description.
func (d *OpenAIDetector) Description() string {
	return "OpenAI API key detector (sk-...T3BlbkFJ... pattern)"
}

// FromData scans raw data for OpenAI keys.
func (d *OpenAIDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	// Quick keyword pre-check before running expensive regex.
	hasSK := false
	hasSuffix := false
	for i := 0; i < len(data); i++ {
		if !hasSK && i+2 < len(data) && data[i] == 's' && data[i+1] == 'k' && data[i+2] == '-' {
			hasSK = true
		}
		if !hasSuffix && i+7 < len(data) && string(data[i:i+8]) == "T3BlbkFJ" {
			hasSuffix = true
		}
		if hasSK && hasSuffix {
			break
		}
	}
	if !hasSK || !hasSuffix {
		return nil, nil
	}

	matches := extractMatches(openaiRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "openai",
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

// Verify checks an OpenAI key against the API.
func (d *OpenAIDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "openai",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.openai.com/v1/models", nil)
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
	case http.StatusUnauthorized:
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
	DefaultRegistry.Register(NewOpenAI())
}
