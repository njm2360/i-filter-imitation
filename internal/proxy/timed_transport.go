package proxy

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type metaKey struct{}

// requestMeta carries per-request timing and response metadata through the context.
type requestMeta struct {
	start      time.Time
	statusCode int
	bytesSent  atomic.Int64
	// response headers captured after RoundTrip
	contentType string
}

type timedTransport struct {
	base http.RoundTripper
}

func (t *timedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	meta, _ := req.Context().Value(metaKey{}).(*requestMeta)

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if meta != nil {
		meta.statusCode = resp.StatusCode
		meta.contentType = resp.Header.Get("Content-Type")
		// 101 Switching Protocols (WebSocket) needs io.ReadWriteCloser; skip counting.
		if resp.StatusCode != http.StatusSwitchingProtocols {
			resp.Body = &countingReadCloser{ReadCloser: resp.Body, meta: meta}
		}
	}
	return resp, nil
}

type countingReadCloser struct {
	io.ReadCloser
	meta *requestMeta
}

func (c *countingReadCloser) Read(p []byte) (n int, err error) {
	n, err = c.ReadCloser.Read(p)
	c.meta.bytesSent.Add(int64(n))
	return
}
