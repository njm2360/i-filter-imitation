package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// context keys for TLS metadata propagated from CONNECT handler to handlePlain
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

	reqID := newRequestID()

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

	// Wrap conn so the already-buffered bytes from bufio.Reader are drained first.
	wrapped := &connWithReader{Conn: conn, r: bufrw.Reader}

	// TLS handshake with the client using our MITM leaf certificate.
	// r.Context() must not be used here: after Hijack() the server may cancel it.
	tlsConn := tls.Server(wrapped, s.certCache.TLSConfig())
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		if strings.Contains(err.Error(), "remote error: tls:") {
			slog.Warn("possible certificate pinning detected, connection blocked", "host", host, "client", conn.RemoteAddr(), "tls_error", err)
		} else {
			slog.Debug("TLS handshake failed", "host", host, "client", conn.RemoteAddr(), "err", err)
		}
		return
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	tlsVer := tlsVersionStr(state.Version)
	tlsCiph := tlsCipherStr(state.CipherSuite)

	// Serve decrypted HTTP on the TLS connection.
	innerHandler := http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
		if r2.Host == "" {
			r2.Host = host
		}
		r2.URL.Host = host
		r2.URL.Scheme = "https"

		// Inject TLS metadata so handlePlain can log it.
		ctx := context.WithValue(r2.Context(), tlsVersionKey{}, tlsVer)
		ctx = context.WithValue(ctx, tlsCipherKey{}, tlsCiph)
		r2 = r2.WithContext(ctx)

		s.handlePlain(w2, r2, "https", reqID)
	})

	innerSrv := &http.Server{
		Handler:      innerHandler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		ErrorLog:     log.New(filteredWriter{}, "", 0),
	}
	l := newSingleConnListener(tlsConn)
	innerSrv.Serve(l) //nolint:errcheck
}


// connWithReader wraps net.Conn to drain buffered bytes from a bufio.Reader first.
type connWithReader struct {
	net.Conn
	r *bufio.Reader
}

func (c *connWithReader) Read(b []byte) (int, error) { return c.r.Read(b) }

// singleConnListener is a net.Listener that yields exactly one connection.
// The second Accept() blocks until the connection is closed, then returns net.ErrClosed,
// allowing http.Server.Serve to exit cleanly after the single request completes.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) net.Listener {
	l := &singleConnListener{done: make(chan struct{})}
	// Wrap conn so closing it unblocks the second Accept().
	l.conn = &closeNotifyConn{Conn: conn, notify: func() { l.Close() }}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// closeNotifyConn wraps net.Conn and calls notify once when Close is called.
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	notify func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.notify)
	return err
}

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

// filteredWriter drops context.Canceled proxy noise that fires on normal client disconnects.
type filteredWriter struct{}

func (filteredWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "context canceled") {
		return len(p), nil
	}
	slog.Warn("proxy inner error", "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}
