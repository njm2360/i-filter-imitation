package logger

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

const (
	// facility=1 (user-level), severity=6 (info): 1*8+6 = 14
	pri     = 14
	version = 1
	sdID    = "httpAccess@32473"
)

// Format5424 returns a complete RFC 5424 syslog message (no trailing newline).
func Format5424(r AccessRecord, hostname, appName, procID string) []byte {
	ts := r.Time.UTC().Format(time.RFC3339Nano)
	sd := buildSD(r)
	msg := fmt.Sprintf("- %s %s://%s%s %d",
		r.Method, r.Scheme, r.Host, r.Path, r.StatusCode)
	line := fmt.Sprintf("<%d>%d %s %s %s %s - %s %s",
		pri, version, ts,
		nilify(hostname), nilify(appName), nilify(procID),
		sd, msg)
	return []byte(line)
}

func buildSD(r AccessRecord) string {
	fields := []struct{ k, v string }{
		{"requestId", r.RequestID},
		{"clientIP", r.ClientIP},
		{"xForwardedFor", r.XForwardedFor},
		{"method", r.Method},
		{"scheme", r.Scheme},
		{"host", r.Host},
		{"path", r.Path},
		{"status", fmt.Sprintf("%d", r.StatusCode)},
		{"bytes", fmt.Sprintf("%d", r.BytesSent)},
		{"durationMS", fmt.Sprintf("%d", r.DurationMS)},
		{"userAgent", r.UserAgent},
		{"contentType", r.ContentType},
		{"tlsVersion", r.TLSVersion},
		{"tlsCipher", r.TLSCipher},
	}
	var sb strings.Builder
	sb.WriteByte('[')
	sb.WriteString(sdID)
	for _, f := range fields {
		sb.WriteByte(' ')
		sb.WriteString(f.k)
		sb.WriteString(`="`)
		sb.WriteString(escapeSyslog(nilify(f.v)))
		sb.WriteByte('"')
	}
	sb.WriteByte(']')
	return sb.String()
}

// escapeSyslog escapes the three characters forbidden inside SD param values per RFC 5424 §6.3.3.
func escapeSyslog(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

func nilify(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// TLSVersionString converts a tls.Version constant to a human-readable string.
func TLSVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLS0x%04x", v)
	}
}

// TLSCipherString returns the IANA name of a cipher suite, or a hex fallback.
func TLSCipherString(id uint16) string {
	name := tls.CipherSuiteName(id)
	if name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
