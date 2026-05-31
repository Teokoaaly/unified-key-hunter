package tokens

import (
	"sync"
)

// TokenRotator is a thread-safe round-robin token provider. It cycles
// through a list of tokens, returning the next one on each call to Next().
type TokenRotator struct {
	mu     sync.Mutex
	tokens []string
	idx    int
}

// NewTokenRotator creates a new TokenRotator with the given token list.
// If tokens is empty, Next() will return an empty string.
func NewTokenRotator(tokens []string) *TokenRotator {
	// Defensive copy to prevent external mutation
	toks := make([]string, len(tokens))
	copy(toks, tokens)

	return &TokenRotator{
		tokens: toks,
		idx:    0,
	}
}

// Next returns the next token in round-robin order. It is safe for
// concurrent use. If the rotator has no tokens, it returns an empty string.
func (tr *TokenRotator) Next() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if len(tr.tokens) == 0 {
		return ""
	}

	token := tr.tokens[tr.idx]
	tr.idx = (tr.idx + 1) % len(tr.tokens)
	return token
}

// Len returns the number of tokens in the rotator.
func (tr *TokenRotator) Len() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.tokens)
}

// Tokens returns a copy of all tokens in the rotator.
func (tr *TokenRotator) Tokens() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	toks := make([]string, len(tr.tokens))
	copy(toks, tr.tokens)
	return toks
}
