package detectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

var (
	openrouterKeyword1 = []byte("sk-or-v1-")
	openrouterRe       = regexp.MustCompile(`sk-or-v1-[A-Za-z0-9_-]{40,}`)
)

// OpenRouterDetector detects OpenRouter API keys.
type OpenRouterDetector struct {
	client *http.Client
}

// NewOpenRouter creates a new OpenRouterDetector.
func NewOpenRouter() *OpenRouterDetector {
	return &OpenRouterDetector{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keywords returns keywords associated with OpenRouter keys.
func (d *OpenRouterDetector) Keywords() []string {
	return []string{"sk-or-v1-"}
}

// Type returns the provider identifier.
func (d *OpenRouterDetector) Type() string {
	return "openrouter"
}

// Description returns a human-readable description.
func (d *OpenRouterDetector) Description() string {
	return "OpenRouter API key detector (sk-or-v1-... pattern)"
}

// FromData scans raw data for OpenRouter keys.
func (d *OpenRouterDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	hasPrefix := false
	for i := 0; i < len(data); i++ {
		if !hasPrefix && i+8 < len(data) && string(data[i:i+9]) == "sk-or-v1-" {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return nil, nil
	}

	matches := extractMatches(openrouterRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "openrouter",
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

// openrouterCreditsResponse mirrors the credits API response.
type openrouterCreditsResponse struct {
	Data struct {
		TotalCredits   float64 `json:"total_credits"`
		TotalUsage     float64 `json:"total_usage"`
		CreditsPerDollar float64 `json:"credits_per_dollar"`
	} `json:"data"`
}

// Verify checks an OpenRouter key against the API and fetches balance.
func (d *OpenRouterDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "openrouter",
		Redacted: RedactKey(key),
	}

	// First check models endpoint for liveness.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openrouter.ai/api/v1/models", nil)
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

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			r.Status = "DEAD"
		case http.StatusTooManyRequests:
			r.Status = "WARM"
			r.Verified = true
		default:
			r.Status = "DEAD"
		}
		r.Verified = false
		return r, nil
	}

	// Key is valid, now fetch credits/balance.
	r.Status = "LIVE"
	r.Verified = true

	creditsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openrouter.ai/api/v1/credits", nil)
	if err != nil {
		return r, nil // still LIVE, just couldn't get balance
	}
	creditsReq.Header.Set("Authorization", "Bearer "+key)

	creditsResp, err := d.client.Do(creditsReq)
	if err != nil {
		return r, nil // still LIVE, just couldn't get balance
	}
	defer creditsResp.Body.Close()

	if creditsResp.StatusCode == http.StatusOK {
		var cr openrouterCreditsResponse
		if err := json.NewDecoder(creditsResp.Body).Decode(&cr); err == nil {
			r.BalanceUSD = cr.Data.TotalCredits
			r.Balance = cr.Data.TotalCredits
		}
	}

	return r, nil
}

func init() {
	DefaultRegistry.Register(NewOpenRouter())
}
