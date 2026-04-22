package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// context keys for TLS metadata propagated into serveConnLoop
type tlsVersionKey struct{}
type tlsCipherKey struct{}

// newRequestID generates a random 16-byte hex request ID.
func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host // "example.com:443"

	if s.blocklist.IsBlocked(host) {
		serveBlockedPage(w, host)
		return
	}

	rc := http.NewResponseController(w)
	conn, bufrw, err := rc.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Acknowledge the tunnel to the client.
	fmt.Fprint(bufrw, "HTTP/1.1 200 Connection established\r\n\r\n")
	if err := bufrw.Flush(); err != nil {
		return
	}

	// Wrap conn so already-buffered bytes from the outer server are drained first.
	wrapped := &connWithReader{conn: conn, r: bufrw.Reader}

	// TLS MITM handshake with the client.
	tlsConn := tls.Server(wrapped, s.certCache.TLSConfig())
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		if strings.Contains(err.Error(), "remote error: tls:") {
			slog.Warn("possible certificate pinning detected, connection blocked",
				"host", host, "client", conn.RemoteAddr(), "tls_error", err)
		} else {
			slog.Debug("TLS handshake failed",
				"host", host, "client", conn.RemoteAddr(), "err", err)
		}
		return
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()

	// Serve decrypted HTTP requests directly on the TLS connection.
	s.serveConnLoop(tlsConn, "https", host, tlsVersionStr(state.Version), tlsCipherStr(state.CipherSuite))
}

// connWithReader wraps net.Conn to drain buffered bytes from a bufio.Reader first.
type connWithReader struct {
	conn net.Conn
	r    interface{ Read([]byte) (int, error) }
}

func (c *connWithReader) Read(b []byte) (int, error)         { return c.r.Read(b) }
func (c *connWithReader) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *connWithReader) Close() error                       { return c.conn.Close() }
func (c *connWithReader) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *connWithReader) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *connWithReader) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *connWithReader) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *connWithReader) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func tlsVersionStr(v uint16) string {
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

func tlsCipherStr(id uint16) string {
	name := tls.CipherSuiteName(id)
	if name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
