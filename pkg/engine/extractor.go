package engine

import (
	"context"
	"regexp"
	"strings"

	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/detectors"
)

// Extractor extracts potential keys from raw content using regex patterns.
type Extractor struct {
	patterns     []*regexp.Regexp
	providerHints map[string]string // regex index → provider hint
}

// NewExtractor creates a new Extractor with built-in key patterns.
func NewExtractor() *Extractor {
	patterns := []*regexp.Regexp{
		// OpenAI: sk-proj-XXX...T3BlbkFJ... or sk-XXX...T3BlbkFJ...
		regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b`),
		// Anthropic: sk-ant-api03-XXX...AA
		regexp.MustCompile(`\b(sk-ant-(?:api|admin|compat)\d{2}-[A-Za-z0-9_-]{80,})\b`),
		// DeepSeek: sk- followed by 48-64 alphanumeric (not T3BlbkFJ format)
		regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{48,64})\b`),
		// Google AI / Gemini: AIzaSy...
		regexp.MustCompile(`\b(AIzaSy[A-Za-z0-9_-]{33})\b`),
		// Groq: gsk_...
		regexp.MustCompile(`\b(gsk_[A-Za-z0-9]{30,})\b`),
		// HuggingFace: hf_...
		regexp.MustCompile(`\b(hf_[A-Za-z]{2}[A-Za-z0-9]{32})\b`),
		// xAI / Grok: xai-...
		regexp.MustCompile(`\b(xai-[A-Za-z0-9]{30,})\b`),
		// Perplexity: pplx-...
		regexp.MustCompile(`\b(pplx-[A-Za-z0-9]{30,})\b`),
		// Together AI: together_... or tgr_...
		regexp.MustCompile(`\b((?:together|tgr)_[A-Za-z0-9]{25,})\b`),
		// Replicate: r8_...
		regexp.MustCompile(`\b(r8_[A-Za-z0-9]{30,})\b`),
		// OpenRouter: sk-or-v1-...
		regexp.MustCompile(`\b(sk-or-v1-[A-Za-z0-9]{30,})\b`),
		// Cohere: 40-char alphanumeric after "COHERE_API_KEY" or standalone
		regexp.MustCompile(`(?:COHERE_API_KEY|cohere)[\s'"=:]+([A-Za-z0-9]{40})\b`),
		// Mistral: 32-char alphanumeric (high FP, only near "MISTRAL" keyword)
		regexp.MustCompile(`(?:MISTRAL_API_KEY|mistral)[\s'"=:]+([A-Za-z0-9]{32})\b`),
		// Fireworks: fw_...
		regexp.MustCompile(`\b(fw_[A-Za-z0-9]{30,})\b`),
		// AI21: AI21-... or 64-char key
		regexp.MustCompile(`\b(AI21-[A-Za-z0-9]{40,})\b`),
		// Voyage: vo-... or vs-...
		regexp.MustCompile(`\b(v[os]-[A-Za-z0-9]{30,})\b`),
		// Generic API keys in env-like context (sk-, api_key, etc.)
		regexp.MustCompile(`(?i)(?:OPENAI|ANTHROPIC|DEEPSEEK|GOOGLE|GROQ|COHERE|MISTRAL|TOGETHER|PERPLEXITY|XAI|HUGGINGFACE|REPLICATE|OPENROUTER|FIREWORKS|AI21|VOYAGE)[\s_]*API[\s_]*KEY[\s'"=:]+([A-Za-z0-9_\-]{20,})`),
	}

	return &Extractor{patterns: patterns}
}

// Extract processes raw content and returns detected key results.
func (e *Extractor) Extract(ctx context.Context, content []byte, source, repo, path, rawURL, line string) []detectors.Result {
	var results []detectors.Result

	contentStr := string(content)

	// Pre-filter: only process lines that look interesting (contain key prefixes)
	// This drastically reduces false positives for large files
	interestingPrefixes := []string{
		"sk-", "sk-ant", "AIza", "gsk_", "hf_", "xai-", "pplx-", "r8_",
		"together_", "tgr_", "sk-or", "fw_", "AI21-", "vo-", "vs-",
		"OPENAI", "ANTHROPIC", "DEEPSEEK", "GOOGLE", "GROQ", "COHERE",
		"MISTRAL", "TOGETHER", "PERPLEXITY", "XAI", "HUGGINGFACE",
		"REPLICATE", "OPENROUTER", "FIREWORKS", "VOYAGE",
		"API_KEY", "API-KEY", "api_key", "api-key",
	}

	if !containsAny(contentStr, interestingPrefixes) {
		return results
	}

	for _, pat := range e.patterns {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		matches := pat.FindAllStringSubmatch(contentStr, -1)
		for _, match := range matches {
			var key string
			for i := len(match) - 1; i >= 1; i-- {
				if match[i] != "" {
					key = strings.TrimSpace(match[i])
					break
				}
			}
			if key == "" {
				key = strings.TrimSpace(match[0])
			}

			// Skip very short keys and obvious false positives
			if len(key) < 20 {
				continue
			}
			// Skip URLs
			if strings.HasPrefix(key, "http") || strings.HasPrefix(key, "//") {
				continue
			}
			// Skip CSS/SVG artifacts (common false positive in web files)
			if strings.Contains(key, "--") && strings.Count(key, "-") > 5 {
				continue
			}

			keyType := guessType(key)

			results = append(results, detectors.Result{
				Key:    key,
				Type:   keyType,
				Source: source,
				Repo:   repo,
				Path:   path,
				RawURL: rawURL,
				Line:   line,
				Status: detectors.StatusUnverified,
			})
		}
	}

	return results
}

// guessType identifies the likely provider from the key format.
func guessType(key string) string {
	k := strings.TrimSpace(key)
	switch {
	case strings.HasPrefix(k, "sk-proj-") || (strings.HasPrefix(k, "sk-") && strings.Contains(k, "T3BlbkFJ")):
		return "openai"
	case strings.HasPrefix(k, "sk-ant-api03-"):
		return "anthropic"
	case strings.HasPrefix(k, "sk-ant-admin-"):
		return "anthropic_admin"
	case strings.HasPrefix(k, "sk-ant-compat-"):
		return "anthropic_compat"
	case strings.HasPrefix(k, "sk-or-v1-"):
		return "openrouter"
	case strings.HasPrefix(k, "sk-") && len(k) >= 48:
		return "deepseek"
	case strings.HasPrefix(k, "AIzaSy"):
		return "gemini"
	case strings.HasPrefix(k, "gsk_"):
		return "groq"
	case strings.HasPrefix(k, "hf_"):
		return "huggingface"
	case strings.HasPrefix(k, "xai-"):
		return "xai"
	case strings.HasPrefix(k, "pplx-"):
		return "perplexity"
	case strings.HasPrefix(k, "together_") || strings.HasPrefix(k, "tgr_"):
		return "together"
	case strings.HasPrefix(k, "r8_"):
		return "replicate"
	case strings.HasPrefix(k, "fw_"):
		return "fireworks"
	case strings.HasPrefix(k, "AI21-"):
		return "ai21"
	case strings.HasPrefix(k, "vo-") || strings.HasPrefix(k, "vs-"):
		return "voyage"
	case strings.HasPrefix(k, "sk-"):
		return "openai" // generic sk- fallback
	default:
		return "unknown"
	}
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
