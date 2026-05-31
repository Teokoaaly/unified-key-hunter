package detectors

import (
	"context"
	"strings"
	"testing"
)

// testDetector is a minimal detector implementation for testing.
type testDetector struct {
	typ     string
	desc    string
	keywords []string
}

func (d *testDetector) Type() string             { return d.typ }
func (d *testDetector) Description() string      { return d.desc }
func (d *testDetector) Keywords() []string       { return d.keywords }
func (d *testDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	return nil, nil
}
func (d *testDetector) Verify(ctx context.Context, key string) (Result, error) {
	return Result{}, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()

	d1 := &testDetector{typ: "openai", desc: "OpenAI detector", keywords: []string{"sk-", "T3BlbkFJ"}}
	d2 := &testDetector{typ: "anthropic", desc: "Anthropic detector", keywords: []string{"sk-ant-api03", "sk-ant-admin"}}
	d3 := &testDetector{typ: "gemini", desc: "Gemini detector", keywords: []string{"AIzaSy"}}

	r.Register(d1)
	r.Register(d2)
	r.Register(d3)

	// Get by name
	got, ok := r.Get("openai")
	if !ok {
		t.Fatal("expected to find openai detector")
	}
	if got.Type() != "openai" {
		t.Fatalf("expected openai, got %q", got.Type())
	}

	got, ok = r.Get("anthropic")
	if !ok {
		t.Fatal("expected to find anthropic detector")
	}
	if got.Type() != "anthropic" {
		t.Fatalf("expected anthropic, got %q", got.Type())
	}

	got, ok = r.Get("gemini")
	if !ok {
		t.Fatal("expected to find gemini detector")
	}
	if got.Type() != "gemini" {
		t.Fatalf("expected gemini, got %q", got.Type())
	}

	// Get non-existent
	_, ok = r.Get("nonexistent")
	if ok {
		t.Fatal("expected to not find nonexistent detector")
	}
}

func TestRegistryAllKeywords(t *testing.T) {
	r := NewRegistry()

	d1 := &testDetector{typ: "openai", keywords: []string{"sk-", "T3BlbkFJ"}}
	d2 := &testDetector{typ: "anthropic", keywords: []string{"sk-ant-api03", "sk-ant-admin"}}
	d3 := &testDetector{typ: "groq", keywords: []string{"gsk_"}}

	r.Register(d1)
	r.Register(d2)
	r.Register(d3)

	keywords := r.AllKeywords()

	// Check all expected keywords are present
	expected := map[string]bool{
		"sk-":          true,
		"t3blbkfj":     true,
		"sk-ant-api03": true,
		"sk-ant-admin": true,
		"gsk_":         true,
	}

	for _, kw := range keywords {
		if !expected[kw] {
			t.Errorf("unexpected keyword: %q", kw)
		}
		delete(expected, kw)
	}

	if len(expected) > 0 {
		t.Errorf("missing keywords: %v", expected)
	}
}

func TestRegistryDetectProvider(t *testing.T) {
	r := NewRegistry()

	d1 := &testDetector{typ: "openrouter", keywords: []string{"sk-or-v1-"}}
	d2 := &testDetector{typ: "anthropic", keywords: []string{"sk-ant-api03"}}
	d3 := &testDetector{typ: "gemini", keywords: []string{"AIzaSy"}}
	d4 := &testDetector{typ: "groq", keywords: []string{"gsk_"}}

	r.Register(d1)
	r.Register(d2)
	r.Register(d3)
	r.Register(d4)

	tests := []struct {
		key      string
		expected string
	}{
		{"sk-or-v1-abc123def456ghi789jkl012mno345pqr678stu", "openrouter"},
		{"sk-ant-api03-xxxABCdefGHIjklMNOpqrSTUvwxYZabcDEFghiJKLmnoPQRstuVWXyz0123456789abcdefghij", "anthropic"},
		{"AIzaSyABCdefGHIjklMNOpqrSTUvwxYZ01234", "gemini"},
		{"gsk_abc123def456ghi789jkl012mno345", "groq"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := r.DetectProvider(tc.key)
			if got != tc.expected {
				t.Errorf("DetectProvider(%q) = %q, want %q", tc.key, got, tc.expected)
			}
		})
	}
}

func TestRedactKey(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"sk-abc...7890", "sk-a******890"},
		{"a", "a"},
		{"ab", "a*"},
		{"abcd", "a***"},
		{"abcde", "a****"},
		{"abcdefghijklmnop", "abcd*********nop"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got := RedactKey(tc.key)
			if got != tc.expected {
				t.Errorf("RedactKey(%q) = %q, want %q", tc.key, got, tc.expected)
			}
		})
	}
}

func TestRedactKeyLongKey(t *testing.T) {
	key := "sk-or-v1-abc123def456ghi789jkl012mno345pqr678stu901vwx"
	got := RedactKey(key)
	if !strings.HasPrefix(got, "sk-o") {
		t.Errorf("expected redacted key to start with 'sk-o', got %q", got)
	}
	if !strings.HasSuffix(got, "vwx") {
		t.Errorf("expected redacted key to end with 'vwx', got %q", got)
	}
	// Length should be: 4 + (len-7) + 3 = len(key)
	if len(got) != len(key) {
		t.Errorf("expected redacted key length %d, got %d", len(key), len(got))
	}
}
