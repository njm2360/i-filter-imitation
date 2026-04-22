package logger

import "time"

// AccessRecord holds all fields captured per HTTP request for audit logging.
type AccessRecord struct {
	Time           time.Time
	RequestID      string
	ClientIP       string
	XForwardedFor  string
	Method         string
	Scheme         string // "http" or "https"
	Host           string
	Path           string // includes raw query
	StatusCode     int
	BytesSent      int64
	DurationMS     int64
	UserAgent      string
	ContentType    string // response Content-Type
	TLSVersion     string // e.g. "TLS1.3", empty for plain HTTP
	TLSCipher      string // e.g. "TLS_AES_128_GCM_SHA256", empty for plain HTTP
}
