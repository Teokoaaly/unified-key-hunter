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
	anthropicKeyword1 = []byte("sk-ant-api03")
	anthropicKeyword2 = []byte("sk-ant-admin")
	anthropicRe       = regexp.MustCompile(`sk-ant-(api|admin|compat)[0-9]{2}-[A-Za-z0-9_-]{80,}`)
)

// AnthropicDetector detects Anthropic API keys.
type AnthropicDetector struct {
	client *http.Client
}

// NewAnthropic creates a new AnthropicDetector.
func NewAnthropic() *AnthropicDetector {
	return &AnthropicDetector{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Keywords returns keywords associated with Anthropic keys.
func (d *AnthropicDetector) Keywords() []string {
	return []string{"sk-ant-api03", "sk-ant-admin"}
}

// Type returns the provider identifier.
func (d *AnthropicDetector) Type() string {
	return "anthropic"
}

// Description returns a human-readable description.
func (d *AnthropicDetector) Description() string {
	return "Anthropic API key detector (sk-ant-(api|admin|compat)XX-... pattern)"
}

// FromData scans raw data for Anthropic keys.
func (d *AnthropicDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	// Quick keyword pre-check.
	hasAPI := false
	hasAdmin := false
	for i := 0; i < len(data); i++ {
		if !hasAPI && i+11 < len(data) && string(data[i:i+12]) == "sk-ant-api03" {
			hasAPI = true
		}
		if !hasAdmin && i+11 < len(data) && string(data[i:i+12]) == "sk-ant-admin" {
			hasAdmin = true
		}
		if hasAPI || hasAdmin {
			break
		}
	}
	if !hasAPI && !hasAdmin {
		return nil, nil
	}

	matches := extractMatches(anthropicRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "anthropic",
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

// Verify checks an Anthropic key against the API.
func (d *AnthropicDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "anthropic",
		Redacted: RedactKey(key),
	}

	payload := map[string]interface{}{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return r, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return r, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

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
	DefaultRegistry.Register(NewAnthropic())
}
