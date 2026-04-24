package logger

import "time"

// AccessRecord holds all fields captured per HTTP request for audit logging.
//
// EventType distinguishes normal traffic from proxy-enforced block events so
// aggregators can split the stream with a single filter (eventType="block").
// BlockReason categorises the block (e.g. "blocklist") for drill-down queries.
type AccessRecord struct {
	Time          time.Time
	RequestID     string
	ClientIP      string
	XForwardedFor string
	Method        string
	Scheme        string // "http" or "https"
	Host          string
	Path          string // includes raw query
	StatusCode    int
	BytesSent     int64
	DurationMS    int64
	UserAgent     string
	ContentType   string // response Content-Type
	TLSVersion    string // e.g. "TLS1.3", empty for plain HTTP
	TLSCipher     string // e.g. "TLS_AES_128_GCM_SHA256", empty for plain HTTP

	EventType   string // "access" (default, set by Format5424 if empty) or "block"
	BlockReason string // populated when EventType=="block"; e.g. "blocklist"
}
