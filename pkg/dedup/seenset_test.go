package dedup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeenSetBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seenset.txt")

	ss, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet: %v", err)
	}
	defer ss.Close()

	// Initially, no keys should be seen
	if ss.Seen("key1") {
		t.Error("key1 should not be seen initially")
	}

	// Add 3 keys
	if err := ss.Add("key1"); err != nil {
		t.Fatalf("Add key1: %v", err)
	}
	if err := ss.Add("key2"); err != nil {
		t.Fatalf("Add key2: %v", err)
	}
	if err := ss.Add("key3"); err != nil {
		t.Fatalf("Add key3: %v", err)
	}

	// Verify Seen returns true for added keys
	for _, key := range []string{"key1", "key2", "key3"} {
		if !ss.Seen(key) {
			t.Errorf("%q should be seen", key)
		}
	}

	// Verify Seen returns false for unknown key
	if ss.Seen("key4") {
		t.Error("key4 should not be seen")
	}

	// Verify Size
	if s := ss.Size(); s != 3 {
		t.Errorf("Size = %d, want 3", s)
	}
}

func TestSeenSetDuplicateAdd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seenset.txt")

	ss, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet: %v", err)
	}
	defer ss.Close()

	// Add key1
	if err := ss.Add("key1"); err != nil {
		t.Fatalf("Add key1: %v", err)
	}

	// Size should be 1
	if s := ss.Size(); s != 1 {
		t.Errorf("Size = %d, want 1", s)
	}

	// Add key1 again (should be no-op)
	if err := ss.Add("key1"); err != nil {
		t.Fatalf("Add key1 again: %v", err)
	}

	// Size should still be 1
	if s := ss.Size(); s != 1 {
		t.Errorf("Size = %d after duplicate add, want 1", s)
	}
}

func TestSeenSetPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seenset.db")

	// Create, add keys, close
	ss, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet: %v", err)
	}

	keys := []string{"sk-...7890", "sk-or-...qrst", "AIzaSy...cdef"}
	for _, k := range keys {
		if err := ss.Add(k); err != nil {
			t.Fatalf("Add %s: %v", k, err)
		}
	}

	if err := ss.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify the file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("persistence file was not created")
	}

	// Reopen and verify keys persist
	ss2, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet (reopen): %v", err)
	}
	defer ss2.Close()

	for _, k := range keys {
		if !ss2.Seen(k) {
			t.Errorf("after reopen, %q should be seen", k)
		}
	}

	if s := ss2.Size(); s != 3 {
		t.Errorf("Size after reopen = %d, want 3", s)
	}
}

func TestSeenSetEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	ss, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet: %v", err)
	}
	defer ss.Close()

	if s := ss.Size(); s != 0 {
		t.Errorf("Size = %d, want 0", s)
	}
}

func TestSeenSetSubdirectoryCreation(t *testing.T) {
	dir := t.TempDir()
	// Nested path where subdirectory does not exist yet
	path := filepath.Join(dir, "subdir", "nested", "seenset.txt")

	ss, err := NewSeenSet(path)
	if err != nil {
		t.Fatalf("NewSeenSet with nested dir: %v", err)
	}
	defer ss.Close()

	if err := ss.Add("testkey"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !ss.Seen("testkey") {
		t.Error("testkey should be seen after add")
	}
}
