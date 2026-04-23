package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/njm2360/i-filter-imitation/internal/logger"
)

var bwPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(io.Discard, transportBufSize)
	},
}

// hop-by-hop headers that must not be forwarded to the client.
var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// serveConnLoop reads HTTP requests from conn and proxies them directly,
// bypassing the inner http.Server / ReverseProxy layer entirely.
// This eliminates chunkWriter overhead, 4 KB write-buffer flushes, and
// per-request http.Server machinery, which are the main throughput bottlenecks.
func (s *Server) serveConnLoop(conn net.Conn, scheme, host, tlsVer, tlsCiph string) {
	reader := bufio.NewReaderSize(conn, transportBufSize)
	cpBuf := make([]byte, transportBufSize)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// Normalise for upstream.
		req.RequestURI = ""
		req.URL.Scheme = scheme
		req.URL.Host = host
		if req.Host == "" {
			req.Host = host
		}

		if s.blocklist.IsBlocked(req.Host) {
			loopForbidden(conn, req.Host)
			drainBody(req.Body)
			return
		}

		// Per-request context (logging + TLS metadata).
		meta := &requestMeta{start: time.Now()}
		ctx := context.WithValue(req.Context(), metaKey{}, meta)
		ctx = context.WithValue(ctx, tlsVersionKey{}, tlsVer)
		ctx = context.WithValue(ctx, tlsCipherKey{}, tlsCiph)
		req = req.WithContext(ctx)

		reqID := newRequestID()
		clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		xff := req.Header.Get("X-Forwarded-For")
		ua := req.Header.Get("User-Agent")
		method := req.Method
		path := req.URL.RequestURI()
		start := meta.start

		resp, rtErr := s.transport.RoundTrip(req)
		drainBody(req.Body) // ensure request body is consumed
		if rtErr != nil {
			loopPlainStatus(conn, http.StatusBadGateway)
			s.emitLog(logger.AccessRecord{
				Time: start, RequestID: reqID, ClientIP: clientIP,
				XForwardedFor: xff, Method: method, Scheme: scheme,
				Host: host, Path: path, StatusCode: http.StatusBadGateway,
				DurationMS: time.Since(start).Milliseconds(),
				UserAgent:  ua, TLSVersion: tlsVer, TLSCipher: tlsCiph,
			})
			return
		}

		status := resp.StatusCode

		// Protocol upgrade (WebSocket etc.): forward ALL headers including
		// Upgrade and Connection (which loopWriteHead would strip), then bridge.
		if status == http.StatusSwitchingProtocols {
			loopWriteUpgradeHead(conn, resp)
			rwc, ok := resp.Body.(io.ReadWriteCloser)
			if !ok {
				// Transport did not expose a writable body; cannot bridge.
				resp.Body.Close()
				return
			}
			loopBridge(conn, rwc)
			resp.Body.Close()
			s.emitLog(logger.AccessRecord{
				Time: start, RequestID: reqID, ClientIP: clientIP,
				XForwardedFor: xff, Method: method, Scheme: scheme,
				Host: host, Path: path, StatusCode: status,
				BytesSent:  meta.bytesSent.Load(),
				DurationMS: time.Since(start).Milliseconds(),
				UserAgent:  ua, TLSVersion: tlsVer, TLSCipher: tlsCiph,
			})
			return
		}

		// SSE: bypass buffering so each event is delivered to the client
		// immediately. Use Connection: close instead of chunked encoding so
		// the raw body bytes can be copied straight to the TLS conn.
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			resp.Close = true
			loopWriteHead(conn, resp)
			io.CopyBuffer(conn, resp.Body, cpBuf) //nolint:errcheck
			resp.Body.Close()
			s.emitLog(logger.AccessRecord{
				Time: start, RequestID: reqID, ClientIP: clientIP,
				XForwardedFor: xff, Method: method, Scheme: scheme,
				Host: host, Path: path, StatusCode: status,
				BytesSent:  meta.bytesSent.Load(),
				DurationMS: time.Since(start).Milliseconds(),
				UserAgent:  ua, ContentType: meta.contentType,
				TLSVersion: tlsVer, TLSCipher: tlsCiph,
			})
			return
		}

		bw := bwPool.Get().(*bufio.Writer)
		bw.Reset(conn)
		loopWriteHead(bw, resp)
		loopWriteBody(bw, resp, cpBuf)
		bw.Flush() //nolint:errcheck
		bwPool.Put(bw)
		resp.Body.Close()

		s.emitLog(logger.AccessRecord{
			Time: start, RequestID: reqID, ClientIP: clientIP,
			XForwardedFor: xff, Method: method, Scheme: scheme,
			Host: host, Path: path, StatusCode: status,
			BytesSent:  meta.bytesSent.Load(),
			DurationMS: time.Since(start).Milliseconds(),
			UserAgent:  ua, ContentType: meta.contentType,
			TLSVersion: tlsVer, TLSCipher: tlsCiph,
		})

		if resp.Close || req.Close {
			return
		}
	}
}

func (s *Server) emitLog(rec logger.AccessRecord) {
	if s.sender != nil {
		s.sender.Send(rec)
	}
}

// loopWriteUpgradeHead writes a 101 response forwarding ALL upstream headers,
// including Upgrade and Connection which are normally stripped as hop-by-hop.
// These headers are required for the client to complete the WebSocket handshake.
func loopWriteUpgradeHead(w io.Writer, resp *http.Response) {
	fmt.Fprintf(w, "HTTP/%d.%d 101 Switching Protocols\r\n", resp.ProtoMajor, resp.ProtoMinor)
	resp.Header.Write(w) //nolint:errcheck
	fmt.Fprint(w, "\r\n")
}

// loopWriteHead writes the HTTP status line + response headers to w,
// stripping hop-by-hop headers and emitting explicit body framing.
// The client connection is always HTTP/1.1, so the status line advertises 1.1
// even when the upstream spoke HTTP/2 — otherwise we'd be handing the browser
// an "HTTP/2.0" status line on a 1.1 byte stream.
func loopWriteHead(w io.Writer, resp *http.Response) {
	text := resp.Status
	if text == "" {
		text = http.StatusText(resp.StatusCode)
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", resp.StatusCode, text)

	for k, vv := range resp.Header {
		if _, skip := hopHeaders[k]; skip {
			continue
		}
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(w, "%s: %s\r\n", k, v)
		}
	}

	// Emit explicit body framing. Without this, synthetic zero-body responses
	// (e.g. the scan-redirect 302) leave the client waiting forever on a
	// keep-alive connection.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		switch {
		case resp.ContentLength >= 0:
			fmt.Fprintf(w, "Content-Length: %d\r\n", resp.ContentLength)
		case resp.Close:
			fmt.Fprint(w, "Connection: close\r\n")
		default:
			fmt.Fprint(w, "Transfer-Encoding: chunked\r\n")
		}
	}

	fmt.Fprint(w, "\r\n")
}

// loopWriteBody streams the response body into w (a pooled bufio.Writer from
// the caller). Reads from resp.Body are coalesced in the buffer before being
// flushed as large TLS writes; the caller is responsible for the final Flush.
func loopWriteBody(w io.Writer, resp *http.Response, buf []byte) {
	if resp.ContentLength == 0 {
		return
	}
	if resp.ContentLength > 0 {
		io.CopyBuffer(w, resp.Body, buf) //nolint:errcheck
		return
	}
	// Unknown length: chunked encoding; w is already buffered so chunk
	// headers and payload are coalesced before hitting TLS.
	cw := &loopChunkedWriter{w: w}
	io.CopyBuffer(cw, resp.Body, buf) //nolint:errcheck
	cw.close()
}

// loopForbidden writes a 403 blocked-page response and closes.
func loopForbidden(w io.Writer, host string) {
	body := fmt.Sprintf(blockedPageHTML, host)
	fmt.Fprintf(w,
		"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// loopPlainStatus writes a minimal error response with no body.
func loopPlainStatus(w io.Writer, code int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code))
}

const bridgeIdleTimeout = 5 * time.Minute

// loopBridge does bidirectional copy between conn and rwc until either closes.
// An idle timeout is enforced: if no data flows for bridgeIdleTimeout, conn is
// closed which unblocks both directions and prevents goroutine leaks.
func loopBridge(conn net.Conn, rwc io.ReadWriteCloser) {
	refresh := func() { conn.SetDeadline(time.Now().Add(bridgeIdleTimeout)) } //nolint:errcheck
	refresh()
	bc := &bridgeConn{Conn: conn, refresh: refresh}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, transportBufSize)
		io.CopyBuffer(rwc, bc, buf)
		rwc.Close()
		close(done)
	}()
	buf := make([]byte, transportBufSize)
	io.CopyBuffer(bc, rwc, buf)
	conn.Close()
	<-done
}

// bridgeConn wraps net.Conn and resets the read/write deadline on every
// successful data transfer, implementing an activity-based idle timeout.
type bridgeConn struct {
	net.Conn
	refresh func()
}

func (b *bridgeConn) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	if n > 0 {
		b.refresh()
	}
	return n, err
}

func (b *bridgeConn) Write(p []byte) (int, error) {
	n, err := b.Conn.Write(p)
	if n > 0 {
		b.refresh()
	}
	return n, err
}

// drainBody discards and closes body to allow connection reuse.
func drainBody(body io.ReadCloser) {
	if body == nil || body == http.NoBody {
		return
	}
	io.Copy(io.Discard, body) //nolint:errcheck
	body.Close()
}

// loopChunkedWriter encodes data as HTTP/1.1 chunked transfer encoding.
type loopChunkedWriter struct {
	w io.Writer
}

func (cw *loopChunkedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(cw.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := cw.w.Write(p)
	if err != nil {
		return n, err
	}
	_, err = io.WriteString(cw.w, "\r\n")
	return n, err
}

func (cw *loopChunkedWriter) close() {
	io.WriteString(cw.w, "0\r\n\r\n") //nolint:errcheck
}
