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
	deepseekKeyword1 = []byte("sk-")
	deepseekKeyword2 = []byte("deepseek")
	deepseekRe       = regexp.MustCompile(`sk-[a-zA-Z0-9]{48,64}`)
)

// DeepSeekDetector detects DeepSeek API keys.
type DeepSeekDetector struct {
	client *http.Client
}

// NewDeepSeek creates a new DeepSeekDetector.
func NewDeepSeek() *DeepSeekDetector {
	return &DeepSeekDetector{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Keywords returns keywords associated with DeepSeek keys.
func (d *DeepSeekDetector) Keywords() []string {
	return []string{"sk-", "deepseek"}
}

// Type returns the provider identifier.
func (d *DeepSeekDetector) Type() string {
	return "deepseek"
}

// Description returns a human-readable description.
func (d *DeepSeekDetector) Description() string {
	return "DeepSeek API key detector (sk-... pattern, 48-64 chars)"
}

// FromData scans raw data for DeepSeek keys.
func (d *DeepSeekDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	// Quick keyword pre-check.
	hasSK := false
	hasDS := false
	for i := 0; i < len(data); i++ {
		if !hasSK && i+2 < len(data) && data[i] == 's' && data[i+1] == 'k' && data[i+2] == '-' {
			hasSK = true
		}
		if !hasDS && i+7 < len(data) && string(data[i:i+8]) == "deepseek" {
			hasDS = true
		}
		if hasSK && hasDS {
			break
		}
	}
	if !hasSK && !hasDS {
		return nil, nil
	}

	matches := extractMatches(deepseekRe, data)
	var results []Result
	for _, m := range matches {
		key := string(m)
		r := Result{
			Key:      key,
			Provider: "deepseek",
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

// deepseekBalanceResponse mirrors the relevant fields from the balance API.
type deepseekBalanceResponse struct {
	BalanceInfos []struct {
		Currency      string `json:"currency"`
		TotalBalance  string `json:"total_balance"`
	} `json:"balance_infos"`
}

const cnyToUSD = 0.138

// Verify checks a DeepSeek key against the balance API.
func (d *DeepSeekDetector) Verify(ctx context.Context, key string) (Result, error) {
	r := Result{
		Key:      key,
		Provider: "deepseek",
		Redacted: RedactKey(key),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deepseek.com/user/balance", nil)
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		r.Status = "DEAD"
		r.Verified = false
		return r, nil
	}

	if resp.StatusCode != http.StatusOK {
		r.Status = "DEAD"
		r.Verified = false
		return r, nil
	}

	var balResp deepseekBalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&balResp); err != nil {
		r.Status = "WARM"
		r.Verified = true
		return r, nil // key is valid but we couldn't parse balance
	}

	r.Status = "LIVE"
	r.Verified = true

	for _, info := range balResp.BalanceInfos {
		var balance float64
		if _, err := fmt.Sscanf(info.TotalBalance, "%f", &balance); err == nil {
			if info.Currency == "CNY" {
				r.BalanceCNY = balance
				r.BalanceUSD = balance * cnyToUSD
			} else if info.Currency == "USD" {
				r.BalanceUSD = balance
				r.BalanceCNY = balance / cnyToUSD
			}
		}
	}

	return r, nil
}

func init() {
	DefaultRegistry.Register(NewDeepSeek())
}
