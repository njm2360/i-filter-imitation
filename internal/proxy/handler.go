package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/njm2360/i-filter-imitation/internal/cert"
	"github.com/njm2360/i-filter-imitation/internal/logger"
	"github.com/njm2360/i-filter-imitation/internal/scan"
)

const scanPrefix = scan.PathPrefix

// Server is the MITM proxy HTTP handler.
type Server struct {
	certCache   *cert.Cache
	sender      *logger.Sender
	tt          *timedTransport
	transport   http.RoundTripper // scanTransport or timedTransport; used by serveConnLoop
	rp          *httputil.ReverseProxy
	blocklist   atomic.Pointer[Blocklist]
	scanHandler http.Handler
	pacContent  []byte // nil means PAC distribution is disabled
	caCertPEM   []byte
	caCertDER   []byte
}

const transportBufSize = 256 * 1024 // 256 KB — reduces syscall count ~64x vs the 4 KB default

// rpBufPool provides reusable copy buffers for httputil.ReverseProxy to avoid
// per-request heap allocations when streaming response bodies.
var rpBufPool = &sync.Pool{New: func() any { b := make([]byte, transportBufSize); return &b }}

type bufPool struct{}

func (bufPool) Get() []byte  { return *rpBufPool.Get().(*[]byte) }
func (bufPool) Put(b []byte) { rpBufPool.Put(&b) }

func NewServer(cc *cert.Cache, sender *logger.Sender, bl *Blocklist, mgr *scan.Manager, pacContent []byte) *Server {
	base := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 128,
		ReadBufferSize:      transportBufSize,
		WriteBufferSize:     transportBufSize,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	tt := &timedTransport{base: base}

	var tr http.RoundTripper = tt
	var scanHandler http.Handler = http.NotFoundHandler()
	if mgr != nil {
		tr = &scanTransport{next: tt, manager: mgr}
		scanHandler = scan.NewHandler(mgr)
	}

	rp := &httputil.ReverseProxy{
		Transport:  tr,
		BufferPool: bufPool{},
		Rewrite: func(pr *httputil.ProxyRequest) {
			// scheme and host are set by handlePlain before the proxy is invoked
			pr.Out.URL.Scheme = pr.In.URL.Scheme
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
		},
	}

	srv := &Server{
		certCache:   cc,
		sender:      sender,
		tt:          tt,
		transport:   tr,
		rp:          rp,
		scanHandler: scanHandler,
		pacContent:  pacContent,
		caCertPEM:   cc.CACertPEM(),
		caCertDER:   cc.CACertDER(),
	}
	if bl != nil {
		srv.blocklist.Store(bl)
	}
	return srv
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	if r.URL.Host == magicHost {
		s.serveMagicHost(w, r)
		return
	}

	if r.URL.Host == "" {
		if strings.HasPrefix(r.URL.Path, scanPrefix) {
			s.scanHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/proxy.pac" && s.pacContent != nil {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Write(s.pacContent) //nolint:errcheck
			return
		}
		// Serve the MITM CA directly so operators can fetch it without going
		// through the proxy itself (e.g. http://<proxy-host>:<port>/cert.crt).
		switch r.URL.Path {
		case "/cert.pem":
			s.serveCertPEM(w)
			return
		case "/cert.crt":
			s.serveCertDER(w)
			return
		}
		http.NotFound(w, r)
		return
	}

	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if s.blocklist.Load().IsBlocked(r.Host) {
		serveBlockedPage(w, r.Host)
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.emitLog(logger.AccessRecord{
			Time:          time.Now(),
			RequestID:     newRequestID(),
			ClientIP:      clientIP,
			XForwardedFor: r.Header.Get("X-Forwarded-For"),
			Method:        r.Method,
			Scheme:        "http",
			Host:          r.Host,
			Path:          r.URL.RequestURI(),
			StatusCode:    http.StatusForbidden,
			UserAgent:     r.Header.Get("User-Agent"),
			EventType:     "block",
			BlockReason:   "blocklist",
		})
		return
	}
	s.handlePlain(w, r, "http", "")
}

// handlePlain proxies a decoded HTTP request and emits an access log entry.
// scheme is "http" or "https"; tlsInfo carries pre-filled TLS fields for HTTPS.
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request, scheme string, requestID string) {
	if requestID == "" {
		requestID = newRequestID()
	}
	r.URL.Scheme = scheme

	meta := &requestMeta{start: time.Now()}
	ctx := context.WithValue(r.Context(), metaKey{}, meta)
	r = r.WithContext(ctx)

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	xff := r.Header.Get("X-Forwarded-For")
	ua := r.Header.Get("User-Agent")
	method := r.Method
	host := r.Host
	path := r.URL.RequestURI()
	start := meta.start

	rw := &responseRecorder{ResponseWriter: w}
	s.rp.ServeHTTP(rw, r)

	tlsVer, _ := r.Context().Value(tlsVersionKey{}).(string)
	tlsCiph, _ := r.Context().Value(tlsCipherKey{}).(string)

	if s.sender == nil {
		return
	}
	s.sender.Send(logger.AccessRecord{
		Time:          start,
		RequestID:     requestID,
		ClientIP:      clientIP,
		XForwardedFor: xff,
		Method:        method,
		Scheme:        scheme,
		Host:          host,
		Path:          path,
		StatusCode:    rw.status,
		BytesSent:     meta.bytesSent.Load(),
		DurationMS:    time.Since(start).Milliseconds(),
		UserAgent:     ua,
		ContentType:   meta.contentType,
		TLSVersion:    tlsVer,
		TLSCipher:     tlsCiph,
	})
}

const blockedPageHTML = `<!DOCTYPE html>
<html lang="ja">
<head><meta charset="UTF-8"><title>アクセスブロック</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.box{background:#fff;border-radius:8px;padding:40px 48px;box-shadow:0 2px 8px rgba(0,0,0,.12);text-align:center;max-width:480px}
h1{color:#d32f2f;margin:0 0 12px}p{color:#555;margin:0}code{background:#eee;padding:2px 6px;border-radius:4px}</style>
</head>
<body><div class="box">
<h1>アクセスブロック</h1>
<p>このサイト (<code>%s</code>) へのアクセスはポリシーによりブロックされています。</p>
</div></body></html>`

func serveBlockedPage(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, blockedPageHTML, host)
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}
