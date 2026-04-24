package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/njm2360/i-filter-imitation/internal/logger"
)

// context keys for TLS metadata propagated into serveConnLoop
type tlsVersionKey struct{}
type tlsCipherKey struct{}

func newRequestID() string {
	return uuid.New().String()
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host // "example.com:443"

	if s.blocklist.Load().IsBlocked(host) {
		w.Header().Set("Connection", "close")
		serveBlockedPage(w, host)
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.emitLog(logger.AccessRecord{
			Time:          time.Now(),
			RequestID:     newRequestID(),
			ClientIP:      clientIP,
			XForwardedFor: r.Header.Get("X-Forwarded-For"),
			Method:        r.Method,
			Scheme:        "https",
			Host:          host,
			StatusCode:    http.StatusForbidden,
			UserAgent:     r.Header.Get("User-Agent"),
			EventType:     "block",
			BlockReason:   "blocklist",
		})
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
	wrapped := &connWithReader{conn: conn, br: bufrw.Reader}

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
	s.serveConnLoop(tlsConn, "https", host, logger.TLSVersionString(state.Version), logger.TLSCipherString(state.CipherSuite))
}

// connWithReader wraps net.Conn to drain buffered bytes from a bufio.Reader first
type connWithReader struct {
	conn net.Conn
	br   *bufio.Reader
}

func (c *connWithReader) Read(b []byte) (int, error) {
	if c.br != nil {
		if c.br.Buffered() > 0 {
			return c.br.Read(b)
		}
		c.br = nil
	}
	return c.conn.Read(b)
}
func (c *connWithReader) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *connWithReader) Close() error                       { return c.conn.Close() }
func (c *connWithReader) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *connWithReader) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *connWithReader) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *connWithReader) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *connWithReader) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
