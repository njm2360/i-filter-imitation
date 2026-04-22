package proxy

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Blocklist holds domains that the proxy should refuse to connect to.
// Entries support exact match ("example.com") and leading-wildcard ("*.example.com").
// A wildcard entry also matches all subdomains at any depth.
type Blocklist struct {
	exact    map[string]struct{}
	suffixes []string // stored as ".example.com" for suffix matching
}

// LoadBlocklist reads a blocklist file.
// Each non-empty, non-comment line is a domain entry.
// Returns nil (no blocking) if path is empty.
func LoadBlocklist(path string) (*Blocklist, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blocklist{exact: make(map[string]struct{})}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if strings.HasPrefix(line, "*.") {
			// "*.example.com" → suffix ".example.com"
			bl.suffixes = append(bl.suffixes, line[1:])
		} else {
			bl.exact[line] = struct{}{}
		}
	}
	return bl, scanner.Err()
}

// IsBlocked reports whether host (with or without port) is on the blocklist.
func (bl *Blocklist) IsBlocked(host string) bool {
	if bl == nil {
		return false
	}
	h := strings.ToLower(host)
	// strip port
	if stripped, _, err := net.SplitHostPort(h); err == nil {
		h = stripped
	}

	if _, ok := bl.exact[h]; ok {
		return true
	}
	for _, suf := range bl.suffixes {
		// suf = ".example.com"
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}
