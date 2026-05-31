package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/engine"
	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/sources"
	"github.com/smartwatchesfans-hue/unified-key-hunter/pkg/storage"
)

func main() {
	// CLI flags.
	run := flag.Bool("run", false, "Execute the key-hunting pipeline")
	sourceFlag := flag.String("source", "all", "Source to use: sourcegraph, github, all")
	outputDir := flag.String("output-dir", "./output", "Output directory for results")
	githubTokens := flag.String("github-tokens", "", "Comma-separated GitHub tokens")
	maxKeys := flag.Int("max-keys", 0, "Maximum unique keys to collect (0 = unlimited)")
	maxDuration := flag.Duration("max-duration", 0, "Maximum run duration (e.g., 30m, 1h)")
	queriesFile := flag.String("queries", "", "File with search queries (one per line)")
	queriesFlag := flag.String("query", "", "Search query (can be specified multiple times, comma-separated)")
	fetchContent := flag.Bool("fetch-content", true, "Fetch raw file content for scanning (required for full keys)")
	exportCSV := flag.String("export-csv", "", "Export results to CSV file")
	alertsJSONL := flag.String("alerts-jsonl", "", "Export high-balance alerts to JSONL")
	minBalance := flag.Float64("min-balance", 0.0, "Minimum balance for alerts")

	flag.Parse()

	if !*run {
		fmt.Fprintf(os.Stderr, "Usage: ukh --run [flags]\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Prepare output directory.
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	// Build source list.
	var srcList []sources.Source
	if *sourceFlag == "all" || *sourceFlag == "sourcegraph" {
		srcList = append(srcList, sources.NewSourcegraphClient())
	}
	if *sourceFlag == "all" || *sourceFlag == "github" {
		tokens := parseTokens(*githubTokens)
		if len(tokens) == 0 {
			// Try environment variable.
			if envTokens := os.Getenv("GITHUB_TOKENS"); envTokens != "" {
				tokens = parseTokens(envTokens)
			}
		}
		if len(tokens) == 0 {
			log.Println("warning: no GitHub tokens provided, GitHub source will fail")
			tokens = []string{""} // Will get auth errors but won't crash.
		}
		srcList = append(srcList, sources.NewGitHubClient(tokens))
	}

	if len(srcList) == 0 {
		log.Fatalf("no sources configured")
	}

	// Build queries.
	queries := buildQueries(*queriesFile, *queriesFlag)
	if len(queries) == 0 {
		queries = []string{
			`"(0x)?[0-9a-fA-F]{64}"`,
			`"-----BEGIN.*PRIVATE KEY-----"`,
			`sk-[A-Za-z0-9]{32,}`,
			`"5[KL][1-9A-HJ-NP-Za-km-z]{50,51}"`,
		}
	}

	// Initialize storage.
	dbPath := filepath.Join(*outputDir, "keys.json")
	db := storage.NewKeysDB(dbPath)
	if err := db.Load(); err != nil {
		log.Printf("warning: could not load existing DB: %v", err)
	}

	log.Printf("loaded %d existing keys from %s", db.Count(), dbPath)
	log.Printf("sources: %s", sourceNames(srcList))
	log.Printf("queries: %d", len(queries))
	log.Printf("output dir: %s", *outputDir)

	// Build pipeline config.
	config := engine.Config{
		Sources:      srcList,
		Queries:      queries,
		FetchContent: *fetchContent,
		MaxKeys:      *maxKeys,
		MaxDuration:  *maxDuration,
	}

	// Setup graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	// Run pipeline.
	pipeline := engine.NewPipeline(config, db)
	start := time.Now()

	log.Println("starting pipeline...")
	if err := pipeline.Run(ctx); err != nil {
		log.Printf("pipeline error: %v", err)
	}

	elapsed := time.Since(start)
	stats := db.Stats()
	log.Printf("pipeline finished in %s", elapsed)
	log.Printf("stats: total=%d verified=%d unverified=%d empty=%d error=%d with_balance=%d",
		stats["total"], stats["verified"], stats["unverified"],
		stats["empty"], stats["error"], stats["with_balance"])

	// Export CSV if requested.
	csvPath := *exportCSV
	if csvPath == "" {
		csvPath = filepath.Join(*outputDir, "keys.csv")
	}
	if err := db.ExportCSV(csvPath); err != nil {
		log.Printf("export csv error: %v", err)
	} else {
		log.Printf("exported CSV to %s", csvPath)
	}

	// Export alerts JSONL if requested.
	jsonlPath := *alertsJSONL
	if jsonlPath == "" && *minBalance > 0 {
		jsonlPath = filepath.Join(*outputDir, "telegram_alerts.jsonl")
	}
	if *minBalance > 0 || *alertsJSONL != "" {
		balance := *minBalance
		if balance <= 0 {
			balance = 0.01 // Default minimum.
		}
		if err := db.AlertsJSONL(jsonlPath, balance); err != nil {
			log.Printf("alerts jsonl error: %v", err)
		} else {
			log.Printf("exported alerts JSONL to %s (min balance: %.2f)", jsonlPath, balance)
		}
	}

	// Final save.
	if err := db.Save(); err != nil {
		log.Printf("final save error: %v", err)
	}

	log.Println("done.")
}

// parseTokens splits a comma-separated token string and trims whitespace.
func parseTokens(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var tokens []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

// buildQueries reads queries from a file and/or flag.
func buildQueries(file, flag string) []string {
	var queries []string

	if flag != "" {
		queries = append(queries, strings.Split(flag, ",")...)
	}

	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("warning: could not read queries file %q: %v", file, err)
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					queries = append(queries, line)
				}
			}
		}
	}

	// Trim whitespace from all queries.
	for i, q := range queries {
		queries[i] = strings.TrimSpace(q)
	}

	return queries
}

// sourceNames returns a comma-separated list of source names.
func sourceNames(srcs []sources.Source) string {
	names := make([]string, len(srcs))
	for i, s := range srcs {
		names[i] = s.Name()
	}
	return strings.Join(names, ", ")
}
