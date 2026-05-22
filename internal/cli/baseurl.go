package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrNoBaseURL = errors.New("no base_url file")

func baseURLPath(dataDir string) string {
	return filepath.Join(dataDir, "base_url")
}

func SaveBaseURL(dataDir, url string) error {
	return os.WriteFile(baseURLPath(dataDir), []byte(url+"\n"), 0644)
}

func LoadBaseURL(dataDir string) (string, error) {
	b, err := os.ReadFile(baseURLPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoBaseURL
	}
	if err != nil {
		return "", fmt.Errorf("read base_url: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
