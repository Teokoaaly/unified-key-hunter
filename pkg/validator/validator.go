package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Classify determines whether a key is LIVE, WARM, or DEAD based on the
// HTTP status code and response body returned when testing the key.
//
// LIVE   - key is fully functional
// WARM   - key exists but has issues (rate-limited, expired, low quota)
// DEAD   - key is invalid, revoked, or nonexistent
func Classify(statusCode int, body []byte, provider string) string {
	// Normalize provider to lowercase for comparison
	p := strings.ToLower(provider)

	switch {
	case p == "deepseek":
		return classifyDeepSeek(statusCode, body)
	case p == "openrouter":
		return classifyOpenRouter(statusCode, body)
	default:
		return classifyGeneric(statusCode, body)
	}
}

// classifyDeepSeek interprets DeepSeek API responses.
func classifyDeepSeek(statusCode int, body []byte) string {
	// 200 OK with valid response = LIVE
	if statusCode == http.StatusOK {
		// If the response contains balance info or valid model list, it's LIVE
		var resp struct {
			BalanceInfos []struct {
				Currency        string `json:"currency"`
				TotalBalance    string `json:"total_balance"`
				ToppedUpBalance string `json:"topped_up_balance"`
			} `json:"balance_infos"`
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &resp) == nil {
			if len(resp.BalanceInfos) > 0 || len(resp.Data) > 0 {
				return "LIVE"
			}
		}
		// 200 but no recognizable payload — treat as LIVE if 200
		return "LIVE"
	}

	// 401 = bad auth = DEAD
	if statusCode == http.StatusUnauthorized {
		return "DEAD"
	}

	// 402 Payment Required = insufficient balance = WARM
	if statusCode == http.StatusPaymentRequired {
		return "WARM"
	}

	// 403 Forbidden = revoked/blocked = DEAD
	if statusCode == http.StatusForbidden {
		return "DEAD"
	}

	// 429 Too Many Requests = rate limited = WARM
	if statusCode == http.StatusTooManyRequests {
		return "WARM"
	}

	// 5xx = server issues = WARM (key might still be good)
	if statusCode >= 500 {
		return "WARM"
	}

	// 4xx (other than above) = likely DEAD
	if statusCode >= 400 {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "expired") || strings.Contains(bodyStr, "quota") || strings.Contains(bodyStr, "rate") {
			return "WARM"
		}
		return "DEAD"
	}

	// Default: LIVE for 2xx, DEAD for anything else unexpected
	if statusCode >= 200 && statusCode < 300 {
		return "LIVE"
	}
	return "DEAD"
}

// classifyOpenRouter interprets OpenRouter API responses.
func classifyOpenRouter(statusCode int, body []byte) string {
	if statusCode == http.StatusOK {
		return "LIVE"
	}
	if statusCode == http.StatusUnauthorized {
		return "DEAD"
	}
	if statusCode == http.StatusPaymentRequired {
		return "WARM"
	}
	if statusCode == http.StatusForbidden {
		return "DEAD"
	}
	if statusCode == http.StatusTooManyRequests {
		return "WARM"
	}
	if statusCode >= 500 {
		return "WARM"
	}
	if statusCode >= 400 {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "insufficient_credits") || strings.Contains(bodyStr, "quota") || strings.Contains(bodyStr, "rate") {
			return "WARM"
		}
		return "DEAD"
	}
	if statusCode >= 200 && statusCode < 300 {
		return "LIVE"
	}
	return "DEAD"
}

// classifyGeneric provides a default classification for unknown providers.
func classifyGeneric(statusCode int, body []byte) string {
	if statusCode == http.StatusOK {
		return "LIVE"
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return "DEAD"
	}
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusPaymentRequired {
		return "WARM"
	}
	if statusCode >= 500 {
		return "WARM"
	}
	if statusCode >= 400 {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "expired") || strings.Contains(bodyStr, "quota") || strings.Contains(bodyStr, "rate") {
			return "WARM"
		}
		return "DEAD"
	}
	if statusCode >= 200 && statusCode < 300 {
		return "LIVE"
	}
	return "DEAD"
}

// CheckBalance queries the provider's API to retrieve the current balance
// for the given key. It returns the balance in USD and CNY, or an error if
// the balance cannot be determined.
//
// Supported providers:
//   - deepseek: parses /user/balance endpoint, sums balance_infos
//   - openrouter: parses /api/v1/credits or /api/v1/auth/key endpoint
func CheckBalance(provider string, key string) (float64, float64, error) {
	p := strings.ToLower(provider)

	switch p {
	case "deepseek":
		return checkDeepSeekBalance(key)
	case "openrouter":
		return checkOpenRouterBalance(key)
	default:
		return 0, 0, fmt.Errorf("validator: unsupported provider %q for balance check", provider)
	}
}

// checkDeepSeekBalance calls the DeepSeek balance endpoint.
func checkDeepSeekBalance(key string) (float64, float64, error) {
	url := "https://api.deepseek.com/user/balance"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("validator: DeepSeek returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		BalanceInfos []struct {
			Currency        string `json:"currency"`
			TotalBalance    string `json:"total_balance"`
			ToppedUpBalance string `json:"topped_up_balance"`
		} `json:"balance_infos"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, 0, fmt.Errorf("validator: failed to parse DeepSeek balance: %w", err)
	}

	var usd, cny float64
	for _, bi := range result.BalanceInfos {
		// Parse total_balance as a float
		val := 0.0
		if _, err := fmt.Sscanf(bi.TotalBalance, "%f", &val); err != nil {
			continue
		}
		switch strings.ToUpper(bi.Currency) {
		case "USD":
			usd = val
		case "CNY":
			cny = val
		}
	}

	return usd, cny, nil
}

// checkOpenRouterBalance calls the OpenRouter credits/key endpoint.
func checkOpenRouterBalance(key string) (float64, float64, error) {
	url := "https://openrouter.ai/api/v1/auth/key"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, fmt.Errorf("validator: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("validator: OpenRouter returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			TotalCredits  float64 `json:"total_credits"`
			TotalUsage    float64 `json:"total_usage"`
			Credits       float64 `json:"credits"`
			Usage         float64 `json:"usage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, 0, fmt.Errorf("validator: failed to parse OpenRouter credits: %w", err)
	}

	// OpenRouter credits are in USD.
	// Balance is total_credits - total_usage (or credits - usage).
	balance := result.Data.TotalCredits - result.Data.TotalUsage
	if balance == 0 {
		balance = result.Data.Credits - result.Data.Usage
	}

	return balance, 0, nil
}

// AutoDetectProvider attempts to identify the provider for a given key string
// using prefix heuristics and common key patterns.
//
// Detection rules:
//   - "sk-" prefix + length ~51 → DeepSeek
//   - "sk-or-" prefix → OpenRouter
//   - "sk-" prefix (any other) → OpenAI-compatible (generic)
//   - contains "deepseek" → DeepSeek
//   - contains "openrouter" → OpenRouter
func AutoDetectProvider(key string) string {
	k := strings.TrimSpace(key)
	lower := strings.ToLower(k)

	// Anthropic: must be checked BEFORE generic sk- prefix
	if strings.HasPrefix(lower, "sk-ant-") || strings.Contains(lower, "anthropic") {
		return "anthropic"
	}

	// OpenRouter-specific prefix
	if strings.HasPrefix(lower, "sk-or-") {
		return "openrouter"
	}

	// DeepSeek: sk- prefix with 48-64 chars (not T3BlbkFJ pattern)
	if strings.HasPrefix(lower, "sk-") && !strings.Contains(lower, "t3blbkfj") {
		if strings.Contains(lower, "deepseek") {
			return "deepseek"
		}
		if len(k) >= 48 && len(k) <= 64 {
			return "deepseek"
		}
		// Could be OpenAI
		return "openai"
	}

	// Other prefixes
	if strings.Contains(lower, "deepseek") {
		return "deepseek"
	}
	if strings.Contains(lower, "openrouter") {
		return "openrouter"
	}
	if strings.Contains(lower, "google") || strings.Contains(lower, "gemini") {
		return "google"
	}
	if strings.Contains(lower, "cohere") {
		return "cohere"
	}
	if strings.Contains(lower, "groq") {
		return "groq"
	}

	return ""
}
