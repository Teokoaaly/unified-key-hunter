package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dbFile matches the on-disk keys.json structure from pkg/storage/db.go
type dbFile struct {
	Keys      map[string]keyResult `json:"keys"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type keyResult struct {
	Provider     string    `json:"provider"`
	Redacted     string    `json:"redacted"`
	Verified     bool      `json:"verified"`
	BalanceUSD   float64   `json:"balance_usd"`
	BalanceCNY   float64   `json:"balance_cny"`
	Capabilities []string  `json:"capabilities"`
	Key          string    `json:"key"`
	Type         string    `json:"type"`
	Balance      float64   `json:"balance"`
	Source       string    `json:"source"`
	Path         string    `json:"path"`
	Repo         string    `json:"repo"`
	RawURL       string    `json:"raw_url"`
	Line         string    `json:"line"`
	Status       string    `json:"status"`
	Timestamp    time.Time `json:"timestamp"`
}

type statsResponse struct {
	Total        int     `json:"total"`
	Live         int     `json:"live"`
	Warm         int     `json:"warm"`
	Dead         int     `json:"dead"`
	TotalBalance float64 `json:"total_balance"`
}

var (
	keysPath string
	port     int
)

func main() {
	flag.IntVar(&port, "port", 9120, "HTTP port to listen on")
	flag.StringVar(&keysPath, "keys", "keys.json", "path to keys.json")
	flag.Parse()

	// Ensure index.html path is relative to the binary or the dashboard dir.
	exeDir, err := os.Executable()
	if err != nil {
		exeDir = "."
	} else {
		exeDir = filepath.Dir(exeDir)
	}

	// Try multiple locations for index.html
	indexCandidates := []string{
		filepath.Join(exeDir, "index.html"),
		filepath.Join(exeDir, "dashboard", "index.html"),
		"dashboard/index.html",
		"index.html",
	}

	var indexTmpl *template.Template
	for _, p := range indexCandidates {
		if _, err := os.Stat(p); err == nil {
			indexTmpl = template.Must(template.ParseFiles(p))
			log.Printf("Using index.html from: %s", p)
			break
		}
	}
	if indexTmpl == nil {
		log.Fatal("ERROR: cannot find index.html in any candidate location. Searched: " + strings.Join(indexCandidates, ", "))
	}

	mux := http.NewServeMux()

	// Serve dashboard HTML
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := indexTmpl.Execute(w, nil); err != nil {
			log.Printf("ERROR rendering template: %v", err)
		}
	})

	// API: return raw keys.json
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(keysPath)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"cannot read keys.json: %v"}`, err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
	})

	// API: computed stats
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := computeStats(keysPath)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(stats)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Unified Key Hunter Dashboard listening on http://localhost%s", addr)
	log.Printf("Keys file: %s", keysPath)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func computeStats(path string) (*statsResponse, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}

	var db dbFile
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", path, err)
	}

	stats := &statsResponse{}
	var totalBalance float64

	for _, r := range db.Keys {
		stats.Total++
		switch strings.ToLower(r.Status) {
		case "verified":
			stats.Live++
		case "unverified":
			stats.Warm++
		default:
			stats.Dead++
		}
		if r.Balance > 0 {
			totalBalance += r.Balance
		}
	}

	stats.TotalBalance = math.Round(totalBalance*100) / 100
	return stats, nil
}
