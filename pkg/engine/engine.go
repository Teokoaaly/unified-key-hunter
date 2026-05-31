package engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/detectors"
	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/sources"
	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/storage"
)

// Config holds the pipeline configuration.
type Config struct {
	// Sources is the list of sources to query.
	Sources []sources.Source

	// Queries is the list of search queries to run.
	Queries []string

	// FetchContent controls whether raw content is fetched for each match.
	FetchContent bool

	// MaxKeys stops the pipeline after this many unique keys are found.
	// 0 means no limit.
	MaxKeys int

	// MaxDuration stops the pipeline after this duration.
	// 0 means no limit.
	MaxDuration time.Duration
}

// Pipeline orchestrates the full key-hunting workflow.
type Pipeline struct {
	config    Config
	seen      *SeenSet
	extractor *Extractor
	db        *storage.KeysDB
	uniqueKeyCount int // tracks unique keys for MaxKeys limit, separate from seen (which tracks files)
}

// NewPipeline creates a new Pipeline.
func NewPipeline(config Config, db *storage.KeysDB) *Pipeline {
	return &Pipeline{
		config:    config,
		seen:      NewSeenSet(),
		extractor: NewExtractor(),
		db:        db,
	}
}

// Run executes the pipeline until completion or context cancellation.
func (p *Pipeline) Run(ctx context.Context) error {
	// Apply timeout if configured.
	runCtx := ctx
	var cancel context.CancelFunc
	if p.config.MaxDuration > 0 {
		runCtx, cancel = context.WithTimeout(ctx, p.config.MaxDuration)
		defer cancel()
	}

	// Fan-out: run all sources for all queries.
	var wg sync.WaitGroup
	resultsCh := make(chan []detectors.Result, 100)

	for _, src := range p.config.Sources {
		for _, q := range p.config.Queries {
			wg.Add(1)
			go func(src sources.Source, query string) {
				defer wg.Done()
				p.runSourceQuery(runCtx, src, query, resultsCh)
			}(src, q)
		}
	}

	// Fan-in: collect results and merge into storage.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	totalProcessed := 0
	totalMerged := 0
	lastSave := time.Now()

	for results := range resultsCh {
		if len(results) == 0 {
			continue
		}
		totalProcessed += len(results)

		// Apply max keys limit.
		if p.config.MaxKeys > 0 && p.uniqueKeyCount >= p.config.MaxKeys {
			if cancel != nil {
				cancel()
			}
			break
		}

		merged := p.db.Merge(results)
		totalMerged += merged
		p.uniqueKeyCount += merged
		if merged > 0 {
			log.Printf("engine: merged %d keys (total unique: %d)", merged, p.db.Count())
		}

		// Save periodically (every 5 seconds or every 100 results).
		if merged > 0 && (time.Since(lastSave) > 5*time.Second || totalMerged%100 == 0) {
			if err := p.db.Save(); err != nil {
				log.Printf("engine: save error: %v", err)
			}
			lastSave = time.Now()
		}
	}

	// Final save.
	if err := p.db.Save(); err != nil {
		return fmt.Errorf("engine: final save: %w", err)
	}

	log.Printf("engine: processed %d results, merged %d unique keys (total DB: %d)",
		totalProcessed, totalMerged, p.db.Count())

	return nil
}

func (p *Pipeline) runSourceQuery(ctx context.Context, src sources.Source, query string, resultsCh chan<- []detectors.Result) {
	matchCh, errCh := src.Search(ctx, query)

	// Process matches concurrently to avoid sequential HTTP fetch bottlenecks.
	const workers = 10
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for match := range matchCh {
				// Use a background context with per-request timeout for fetch
				fetchCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				results := p.processMatch(fetchCtx, src, match, query)
				cancel()
				if len(results) > 0 {
					select {
					case <-ctx.Done():
						return
					case resultsCh <- results:
					}
				}
			}
		}()
	}

	// Drain errCh and wait for all workers to finish
	go func() {
		for err := range errCh {
			if err != nil {
				log.Printf("engine: source %q query %q: error: %v", src.Name(), query, err)
			}
		}
	}()
	log.Printf("engine: waiting for %d workers to finish...", workers)
	wg.Wait()
	log.Printf("engine: all workers finished for source %q", src.Name())
}

func (p *Pipeline) processMatch(ctx context.Context, src sources.Source, match sources.Match, query string) []detectors.Result {
	// Deduplicate by repo:path combo.
	dedupKey := fmt.Sprintf("%s:%s", match.Repo, match.Path)
	if !p.seen.Add(dedupKey) {
		return nil
	}

	match.Source = src.Name()
	match.Query = query

	// Try to fetch raw content when enabled.
	if p.config.FetchContent {
		content, err := p.fetchContent(ctx, src, match)
		if err != nil {
			log.Printf("engine: fetch error %s/%s: %v, falling back to line content", match.Repo, match.Path, err)
		}
		if content != nil && len(content) > 0 {
			results := p.extractor.Extract(ctx, content, match.Source, match.Repo, match.Path, match.RawURL, match.Line)
			if len(results) > 0 {
				log.Printf("engine: found %d keys in %s/%s", len(results), match.Repo, match.Path)
			}
			return p.filterResults(results)
		}
	}

	// Fallback: use Line content directly from Sourcegraph (already has context)
	if match.Line != "" {
		results := p.extractor.Extract(ctx, []byte(match.Line), match.Source, match.Repo, match.Path, match.RawURL, match.Line)
		if len(results) > 0 {
			log.Printf("engine: found %d keys (line fallback) in %s/%s", len(results), match.Repo, match.Path)
		}
		return p.filterResults(results)
	}

	return nil
}

func (p *Pipeline) filterResults(results []detectors.Result) []detectors.Result {
	var filtered []detectors.Result
	for _, r := range results {
		if r.Key == "" {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// fetchContent fetches raw content for a match based on the source type.
func (p *Pipeline) fetchContent(ctx context.Context, src sources.Source, match sources.Match) ([]byte, error) {
	switch client := src.(type) {
	case *sources.GitHubClient:
		return client.FetchRawContent(ctx, match.Repo, match.Path)
	case *sources.SourcegraphClient:
		if match.RawURL != "" {
			return client.FetchRawContent(ctx, match.RawURL)
		}
		return nil, fmt.Errorf("sourcegraph: no raw URL for %s/%s", match.Repo, match.Path)
	default:
		return nil, fmt.Errorf("unknown source type")
	}
}
