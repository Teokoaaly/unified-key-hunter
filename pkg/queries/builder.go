package queries

import (
	"fmt"
	"strings"
)

// ProviderQueries holds the search query templates for each provider.
type ProviderQueries struct {
	Name    string
	Queries []string
}

// AllProviders returns the list of all 16 supported providers with their queries.
func AllProviders() []ProviderQueries {
	return []ProviderQueries{
		{
			Name: "openai",
			Queries: []string{
				"sk- file:.env",
				"sk-proj- file:.env",
				"T3BlbkFJ file:.env",
				"OPENAI_API_KEY file:.env",
				"openai file:.env",
			},
		},
		{
			Name: "anthropic",
			Queries: []string{
				"sk-ant-api file:.env",
				"sk-ant-admin file:.env",
				"sk-ant-compat file:.env",
				"ANTHROPIC_API_KEY file:.env",
				"x-api-key file:.env anthropic",
			},
		},
		{
			Name: "deepseek",
			Queries: []string{
				"sk- file:.env deepseek",
				"DEEPSEEK_API_KEY file:.env",
				"deepseek file:.env sk-",
				"api.deepseek.com file:.env",
			},
		},
		{
			Name: "google",
			Queries: []string{
				"AIza file:.env",
				"GEMINI_API_KEY file:.env",
				"GOOGLE_API_KEY file:.env",
				"generativelanguage.googleapis.com file:.env",
			},
		},
		{
			Name: "github",
			Queries: []string{
				"ghp_ file:.env",
				"gho_ file:.env",
				"ghu_ file:.env",
				"ghs_ file:.env",
				"ghr_ file:.env",
				"GITHUB_TOKEN file:.env",
				"GITHUB_KEY file:.env",
			},
		},
		{
			Name: "gitlab",
			Queries: []string{
				"glpat- file:.env",
				"GITLAB_TOKEN file:.env",
				"GITLAB_PRIVATE_TOKEN file:.env",
				"GITLAB_ACCESS_TOKEN file:.env",
			},
		},
		{
			Name: "aws",
			Queries: []string{
				"AKIA file:.env",
				"ASIA file:.env",
				"AWS_ACCESS_KEY_ID file:.env",
				"AWS_SECRET_ACCESS_KEY file:.env",
				"AWS_SESSION_TOKEN file:.env",
				"aws_access_key_id file:.env",
			},
		},
		{
			Name: "slack",
			Queries: []string{
				"xoxb- file:.env",
				"xoxp- file:.env",
				"xoxa- file:.env",
				"xoxr- file:.env",
				"SLACK_BOT_TOKEN file:.env",
				"SLACK_TOKEN file:.env",
				"SLACK_WEBHOOK file:.env",
			},
		},
		{
			Name: "stripe",
			Queries: []string{
				"sk_live_ file:.env",
				"sk_test_ file:.env",
				"rk_live_ file:.env",
				"rk_test_ file:.env",
				"STRIPE_API_KEY file:.env",
				"STRIPE_SECRET_KEY file:.env",
			},
		},
		{
			Name: "twilio",
			Queries: []string{
				"SK file:.env twilio",
				"TWILIO_ACCOUNT_SID file:.env",
				"TWILIO_AUTH_TOKEN file:.env",
				"TWILIO_API_KEY file:.env",
				"TWILIO_API_SECRET file:.env",
				"api.twilio.com file:.env",
			},
		},
		{
			Name: "sendgrid",
			Queries: []string{
				"SG. file:.env",
				"SENDGRID_API_KEY file:.env",
				"sendgrid file:.env api",
				"api.sendgrid.com file:.env",
			},
		},
		{
			Name: "mailgun",
			Queries: []string{
				"key- file:.env mailgun",
				"MAILGUN_API_KEY file:.env",
				"MAILGUN_PRIVATE_KEY file:.env",
				"MAILGUN_PUBLIC_KEY file:.env",
				"api.mailgun.net file:.env",
			},
		},
		{
			Name: "huggingface",
			Queries: []string{
				"hf_ file:.env",
				"HUGGINGFACE_API_KEY file:.env",
				"HUGGINGFACE_TOKEN file:.env",
				"HF_TOKEN file:.env",
				"huggingface.co file:.env api",
			},
		},
		{
			Name: "cohere",
			Queries: []string{
				"COHERE_API_KEY file:.env",
				"cohere file:.env api",
				"api.cohere.ai file:.env",
				"trial key file:.env cohere",
			},
		},
		{
			Name: "replicate",
			Queries: []string{
				"r8_ file:.env",
				"REPLICATE_API_TOKEN file:.env",
				"REPLICATE_API_KEY file:.env",
				"api.replicate.com file:.env",
			},
		},
		{
			Name: "groq",
			Queries: []string{
				"gsk_ file:.env",
				"GROQ_API_KEY file:.env",
				"groq file:.env api",
				"api.groq.com file:.env",
			},
		},
	}
}

// BuildQueries returns the search query templates for a given provider.
// These queries are designed for Sourcegraph/GitHub search syntax.
func BuildQueries(provider string) []string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	for _, pq := range AllProviders() {
		if pq.Name == provider {
			out := make([]string, len(pq.Queries))
			copy(out, pq.Queries)
			return out
		}
	}
	return nil
}

// BuildAllQueries returns all queries for all 16 providers as a flat slice.
func BuildAllQueries() []string {
	var all []string
	for _, pq := range AllProviders() {
		all = append(all, pq.Queries...)
	}
	return all
}

// QuerySummary returns a formatted string listing all providers and their query counts.
func QuerySummary() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Query coverage: %d providers\n\n", len(AllProviders())))
	for _, pq := range AllProviders() {
		b.WriteString(fmt.Sprintf("  %s: %d queries\n", pq.Name, len(pq.Queries)))
	}
	return b.String()
}

// Providers returns the list of all supported provider names.
func Providers() []string {
	all := AllProviders()
	names := make([]string, len(all))
	for i, pq := range all {
		names[i] = pq.Name
	}
	return names
}
