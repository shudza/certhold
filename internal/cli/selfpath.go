package cli

import (
	"os"
)

func existsFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

// firstSelfHomeUser scans <data-dir>/self/home/ and returns the first
// subdirectory name. The init/rekey code path only ever writes one entry here
// for v1 (the manager's --user). Returns ("", false) if the directory is
// missing or has no entries.
func firstSelfHomeUser(homeBase string) (string, bool) {
	entries, err := os.ReadDir(homeBase)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			return e.Name(), true
		}
	}
	return "", false
}
