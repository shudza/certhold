package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadBaseURL_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := "https://192.168.1.205:8443"
	if err := SaveBaseURL(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "base_url"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw) != want+"\n" {
		t.Errorf("on-disk = %q, want %q", raw, want+"\n")
	}

	got, err := LoadBaseURL(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestLoadBaseURL_Missing(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadBaseURL(dir)
	if !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("got %v want ErrNoBaseURL", err)
	}
}
