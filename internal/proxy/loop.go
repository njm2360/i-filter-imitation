package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/njm2360/i-filter-imitation/internal/logger"
)

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
				UserAgent: ua, TLSVersion: tlsVer, TLSCipher: tlsCiph,
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
				BytesSent: meta.bytesSent.Load(),
				DurationMS: time.Since(start).Milliseconds(),
				UserAgent: ua, TLSVersion: tlsVer, TLSCipher: tlsCiph,
			})
			return
		}

		// Write status + headers, then stream body with a large buffer.
		loopWriteHead(conn, resp)
		loopWriteBody(conn, resp, cpBuf)
		resp.Body.Close()

		s.emitLog(logger.AccessRecord{
			Time: start, RequestID: reqID, ClientIP: clientIP,
			XForwardedFor: xff, Method: method, Scheme: scheme,
			Host: host, Path: path, StatusCode: status,
			BytesSent:   meta.bytesSent.Load(),
			DurationMS:  time.Since(start).Milliseconds(),
			UserAgent:   ua, ContentType: meta.contentType,
			TLSVersion:  tlsVer, TLSCipher: tlsCiph,
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
// stripping hop-by-hop headers and adding Transfer-Encoding: chunked
// when Content-Length is unknown.
func loopWriteHead(w io.Writer, resp *http.Response) {
	text := resp.Status
	if text == "" {
		text = http.StatusText(resp.StatusCode)
	}
	fmt.Fprintf(w, "HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, text)

	for k, vv := range resp.Header {
		if _, skip := hopHeaders[k]; skip {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(w, "%s: %s\r\n", k, v)
		}
	}

	// Transport removes Transfer-Encoding after decoding; re-add chunked
	// when body length is unknown.
	if resp.ContentLength < 0 && resp.StatusCode != http.StatusSwitchingProtocols {
		fmt.Fprint(w, "Transfer-Encoding: chunked\r\n")
	}

	fmt.Fprint(w, "\r\n")
}

// loopWriteBody streams the response body to w with a large copy buffer.
// For responses with unknown Content-Length it applies chunked encoding
// using the same buf so the chunk headers and payload are accumulated in a
// 256 KB bufio.Writer before hitting TLS, avoiding small TLS records.
func loopWriteBody(w io.Writer, resp *http.Response, buf []byte) {
	if resp.ContentLength == 0 {
		return
	}
	if resp.ContentLength > 0 {
		// Known length: straight copy, one large write per buffer fill.
		io.CopyBuffer(w, resp.Body, buf) //nolint:errcheck
		return
	}
	// Unknown length: wrap w in a large bufio.Writer so chunk headers and
	// payload are coalesced into a single TLS write per buffer flush.
	bw := bufio.NewWriterSize(w, len(buf))
	cw := &loopChunkedWriter{w: bw}
	io.CopyBuffer(cw, resp.Body, buf) //nolint:errcheck
	cw.close()
	bw.Flush() //nolint:errcheck
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

// loopBridge does bidirectional copy between conn and rwc until either closes.
func loopBridge(conn net.Conn, rwc io.ReadWriteCloser) {
	done := make(chan struct{})
	go func() {
		io.Copy(rwc, conn) //nolint:errcheck
		rwc.Close()
		close(done)
	}()
	io.Copy(conn, rwc) //nolint:errcheck
	<-done
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
