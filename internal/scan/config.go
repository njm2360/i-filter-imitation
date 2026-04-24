package scan

import (
	"strings"
)

// MimeRule is one entry in the scan allowlist.
// Pattern is either an exact MIME type ("application/pdf") or a prefix
// wildcard ("application/x-*"). IsPrefix must be true for wildcards.
type MimeRule struct {
	Pattern  string `json:"pattern"`
	IsPrefix bool   `json:"is_prefix"`
	Enabled  bool   `json:"enabled"`
}

// ScanConfig holds the runtime scan policy loaded from the database.
type ScanConfig struct {
	Enabled   bool       `json:"enabled"`
	MaxSizeMB int64      `json:"max_size_mb"`
	Rules     []MimeRule `json:"rules"`
}

// MaxSizeBytes returns MaxSizeMB converted to bytes.
func (c *ScanConfig) MaxSizeBytes() int64 { return c.MaxSizeMB << 20 }

// IsScannable reports whether the given Content-Type should be scanned.
// Parameters (";charset=…") are stripped before matching.
func (c *ScanConfig) IsScannable(ct string) bool {
	if !c.Enabled {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))

	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		if r.IsPrefix {
			prefix := strings.TrimSuffix(r.Pattern, "*")
			if strings.HasPrefix(ct, prefix) {
				return true
			}
		} else if ct == r.Pattern {
			return true
		}
	}
	return false
}

// DefaultScanConfig returns the scan policy equivalent to the previous
// hardcoded isScannable logic. Used when the database has not been seeded yet.
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Enabled:   true,
		MaxSizeMB: 100,
		Rules: []MimeRule{
			// Archives
			{Pattern: "application/zip", Enabled: true},
			{Pattern: "application/x-zip-compressed", Enabled: true},
			{Pattern: "application/vnd.rar", Enabled: true},
			{Pattern: "application/x-7z-compressed", Enabled: true},
			{Pattern: "application/x-tar", Enabled: true},
			{Pattern: "application/gzip", Enabled: true},
			{Pattern: "application/x-bzip2", Enabled: true},
			{Pattern: "application/x-xz", Enabled: true},
			{Pattern: "application/x-lzma", Enabled: true},
			{Pattern: "application/x-lzip", Enabled: true},
			{Pattern: "application/x-zstd", Enabled: true},
			{Pattern: "application/x-cab", Enabled: true},
			{Pattern: "application/vnd.ms-cab-compressed", Enabled: true},
			{Pattern: "application/x-iso9660-image", Enabled: true},
			{Pattern: "application/x-apple-diskimage", Enabled: true},
			// Executables / binaries
			{Pattern: "application/octet-stream", Enabled: true},
			{Pattern: "binary/octet-stream", Enabled: true},
			{Pattern: "application/x-msdownload", Enabled: true},
			{Pattern: "application/x-dosexec", Enabled: true},
			{Pattern: "application/x-executable", Enabled: true},
			{Pattern: "application/x-msi", Enabled: true},
			{Pattern: "application/x-ms-installer", Enabled: true},
			{Pattern: "application/vnd.microsoft.portable-executable", Enabled: true},
			// Documents
			{Pattern: "application/pdf", Enabled: true},
			{Pattern: "application/rtf", Enabled: true},
			{Pattern: "text/rtf", Enabled: true},
			{Pattern: "application/msword", Enabled: true},
			{Pattern: "application/vnd.ms-excel", Enabled: true},
			{Pattern: "application/vnd.ms-powerpoint", Enabled: true},
			{Pattern: "application/vnd.ms-office", Enabled: true},
			{Pattern: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Enabled: true},
			{Pattern: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Enabled: true},
			{Pattern: "application/vnd.openxmlformats-officedocument.presentationml.presentation", Enabled: true},
			// Java / Android
			{Pattern: "application/java-archive", Enabled: true},
			{Pattern: "application/x-java-archive", Enabled: true},
			{Pattern: "application/vnd.android.package-archive", Enabled: true},
			// Email
			{Pattern: "message/rfc822", Enabled: true},
			{Pattern: "application/vnd.ms-outlook", Enabled: true},
			// application/x-* catch-all (scripts, installers, etc.)
			{Pattern: "application/x-*", IsPrefix: true, Enabled: true},
		},
	}
}
