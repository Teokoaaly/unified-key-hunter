package validator

import (
	"net/http"
	"testing"
)

func TestClassifyGeneric(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		provider   string
		expected   string
	}{
		{"200 LIVE", 200, nil, "openai", "LIVE"},
		{"401 DEAD", 401, nil, "openai", "DEAD"},
		{"429 WARM", 429, nil, "openai", "WARM"},
		{"403 DEAD", 403, nil, "openai", "DEAD"},
		{"402 WARM", 402, nil, "openai", "WARM"},
		{"500 WARM", 500, nil, "openai", "WARM"},
		{"502 WARM", 502, nil, "openai", "WARM"},
		{"404 DEAD", 404, nil, "openai", "DEAD"},
		{"201 LIVE", 201, nil, "openai", "LIVE"},
		{"400 with expired body WARM", 400, []byte("key expired"), "openai", "WARM"},
		{"400 with quota body WARM", 400, []byte("quota exceeded"), "openai", "WARM"},
		{"400 with rate body WARM", 400, []byte("rate limit"), "openai", "WARM"},
		{"400 plain body DEAD", 400, []byte("bad request"), "openai", "DEAD"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.statusCode, tc.body, tc.provider)
			if got != tc.expected {
				t.Errorf("Classify(%d, %q, %q) = %q, want %q",
					tc.statusCode, string(tc.body), tc.provider, got, tc.expected)
			}
		})
	}
}

func TestClassifyDeepSeek(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		expected   string
	}{
		{"200 with balance_info LIVE", 200, []byte(`{"balance_infos":[{"currency":"USD","total_balance":"100.00"}]}`), "LIVE"},
		{"200 with data LIVE", 200, []byte(`{"data":[{"id":"model1"}]}`), "LIVE"},
		{"200 empty LIVE", 200, []byte(`{}`), "LIVE"},
		{"401 DEAD", 401, nil, "DEAD"},
		{"402 WARM", 402, nil, "WARM"},
		{"403 DEAD", 403, nil, "DEAD"},
		{"429 WARM", 429, nil, "WARM"},
		{"500 WARM", 500, nil, "WARM"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.statusCode, tc.body, "deepseek")
			if got != tc.expected {
				t.Errorf("Classify(%d, %q, deepseek) = %q, want %q",
					tc.statusCode, string(tc.body), got, tc.expected)
			}
		})
	}
}

func TestClassifyOpenRouter(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		expected   string
	}{
		{"200 LIVE", 200, nil, "LIVE"},
		{"401 DEAD", 401, nil, "DEAD"},
		{"402 WARM", 402, nil, "WARM"},
		{"403 DEAD", 403, nil, "DEAD"},
		{"429 WARM", 429, nil, "WARM"},
		{"500 WARM", 500, nil, "WARM"},
		{"400 insufficient_credits WARM", 400, []byte("insufficient_credits"), "WARM"},
		{"400 quota WARM", 400, []byte("quota exceeded"), "WARM"},
		{"400 rate WARM", 400, []byte("rate limited"), "WARM"},
		{"400 plain DEAD", 400, []byte("bad request"), "DEAD"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.statusCode, tc.body, "openrouter")
			if got != tc.expected {
				t.Errorf("Classify(%d, %q, openrouter) = %q, want %q",
					tc.statusCode, string(tc.body), got, tc.expected)
			}
		})
	}
}

func TestClassifyCaseInsensitiveProvider(t *testing.T) {
	// Test that provider names are case-insensitive
	tests := []string{"DeepSeek", "DEEPSEEK", "deepseek", "dEEpSEeK", "OpenRouter", "OPENROUTER", "openrouter"}

	for _, provider := range tests {
		t.Run(provider, func(t *testing.T) {
			got := Classify(http.StatusOK, nil, provider)
			if got != "LIVE" {
				t.Errorf("Classify(200, nil, %q) = %q, want LIVE", provider, got)
			}

			got = Classify(http.StatusUnauthorized, nil, provider)
			if got != "DEAD" {
				t.Errorf("Classify(401, nil, %q) = %q, want DEAD", provider, got)
			}

			got = Classify(http.StatusTooManyRequests, nil, provider)
			if got != "WARM" {
				t.Errorf("Classify(429, nil, %q) = %q, want WARM", provider, got)
			}
		})
	}
}

func TestAutoDetectProvider(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"sk-or-...7890", "openrouter"},
		{"SK-OR-...ABCD", "openrouter"},
		{"sk-deepseek-abcdefghijklmnopqrstuvwxyz12345678901234567890", "deepseek"},
		{"deepseek-something", "deepseek"},
		{"sk-abc...5678", "openai"},
		{"sk-ant-...stuv", "anthropic"},
		{"google-api-key", "google"},
		{"something-gemini-here", "google"},
		{"cohere-api-token", "cohere"},
		{"groq-key-here", "groq"},
		{"openrouter-abcdef", "openrouter"},
		{"random-string", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got := AutoDetectProvider(tc.key)
			if got != tc.expected {
				t.Errorf("AutoDetectProvider(%q) = %q, want %q", tc.key, got, tc.expected)
			}
		})
	}
}

func TestAutoDetectProviderDeepSeekLength(t *testing.T) {
	// DeepSeek key with length 51 (starts with sk- and length 50-55, contains deepseek)
	key := "sk-deepseek-abcdefghijklmnopqrstuvwxyz12345678901234"
	if len(key) < 50 || len(key) > 55 {
		t.Fatalf("test key length %d not in expected range", len(key))
	}
	got := AutoDetectProvider(key)
	if got != "deepseek" {
		t.Errorf("AutoDetectProvider(%q) = %q, want deepseek", key, got)
	}
}
