package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/njm2360/i-filter-imitation/internal/scan"
)

// scanTransport wraps timedTransport and intercepts scannable download responses.
type scanTransport struct {
	next    http.RoundTripper
	manager *scan.Manager
}

func (t *scanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Detach from the client request context so that the upstream response body
	// can be read in a background goroutine even after the browser disconnects.
	// context.WithoutCancel preserves all context values (TLS metadata, etc.)
	// while removing propagated cancellation.
	bgReq := req.Clone(context.WithoutCancel(req.Context()))
	resp, err := t.next.RoundTrip(bgReq)
	if err != nil {
		return nil, err
	}

	ct := resp.Header.Get("Content-Type")
	if !isScannable(ct) {
		return resp, nil
	}

	// Skip files that are known to exceed the size limit.
	if resp.ContentLength > t.manager.MaxSize {
		return resp, nil
	}

	// URL cache fast-path. A cached verdict means we've already scanned this
	// exact URL recently, so there's no reason to spin up a new job, redirect
	// through the scan page, or re-buffer the body just to hit the same result.
	//   - Clean:    stream the upstream response straight through.
	//   - Infected: register a preset-infected Job and redirect to the scan
	//               page; the first status poll returns the cached threat
	//               name so the UX is identical to a fresh infected scan.
	if status, threat, ok := t.manager.LookupURL(req.Context(), req.URL.String()); ok {
		switch status {
		case scan.StatusClean:
			return resp, nil
		case scan.StatusInfected:
			resp.Body.Close()
			job := t.manager.NewPresetJob(req, resp, scan.StatusInfected, threat)
			return scanRedirectResponse(job.ID), nil
		}
	}

	if isBrowserRequest(req) {
		return t.handleBrowser(req, resp)
	}
	return t.handleCLI(req, resp)
}

// scanRedirectResponse builds a 302 redirect to the scan result page for the
// given job ID. Shared between the normal browser scan flow and the URL-cache
// infected fast-path so both hit the same UI.
func scanRedirectResponse(jobID string) *http.Response {
	location := "http://" + magicHost + scan.PathResult + "?id=" + jobID
	synth := &http.Response{
		StatusCode:    http.StatusFound,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
	}
	synth.Header.Set("Location", location)
	return synth
}

// handleBrowser starts a background scan and redirects the browser to the
// scan result page hosted on the magic host. The page polls the proxy via
// same-origin relative URLs — no CORS or file:// workarounds needed.
func (t *scanTransport) handleBrowser(req *http.Request, resp *http.Response) (*http.Response, error) {
	job := t.manager.StartBrowserJob(req, resp)
	synth := scanRedirectResponse(job.ID)
	synth.Header.Set("X-Proxy-Scan", "pending:"+job.ID)
	return synth, nil
}

// handleCLI returns the original response headers but replaces the body with a
// trickleBody that drips at ~1 B/s until the ClamAV result is known.
func (t *scanTransport) handleCLI(req *http.Request, resp *http.Response) (*http.Response, error) {
	_, tb := t.manager.StartCLIJob(req, resp)

	synth := &http.Response{
		StatusCode:    resp.StatusCode,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Header:        resp.Header.Clone(),
		Body:          tb,
		ContentLength: -1, // unknown: we control the drip rate
	}
	synth.Header.Del("Content-Length")
	return synth, nil
}

// isBrowserRequest returns true when the request carries an Accept header that
// includes text/html (i.e., it was sent by a browser).
func isBrowserRequest(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isScannable returns true for Content-Types that ClamAV can meaningfully scan.
// Images, audio, video, fonts, and plain-text data formats are excluded.
func isScannable(ct string) bool {
	// Strip parameters ("application/zip; charset=…" → "application/zip").
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	// Skip clearly safe types that ClamAV has no signatures for.
	if strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "font/") {
		return false
	}
	switch ct {
	// Archives
	case "application/zip",
		"application/x-zip-compressed",
		"application/vnd.rar",
		"application/x-7z-compressed",
		"application/x-tar",
		"application/gzip",
		"application/x-bzip2",
		"application/x-xz",
		"application/x-lzma",
		"application/x-lzip",
		"application/x-zstd",
		"application/x-cab",
		"application/vnd.ms-cab-compressed",
		"application/x-iso9660-image",
		"application/x-apple-diskimage",
		// Executables / binaries
		"application/octet-stream",
		"binary/octet-stream",
		"application/x-msdownload",
		"application/x-dosexec",
		"application/x-executable",
		"application/x-msi",
		"application/x-ms-installer",
		"application/vnd.microsoft.portable-executable",
		// Documents
		"application/pdf",
		"application/rtf",
		"text/rtf",
		"application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/vnd.ms-office",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		// Java / Android
		"application/java-archive",
		"application/x-java-archive",
		"application/vnd.android.package-archive",
		// Email
		"message/rfc822",
		"application/vnd.ms-outlook":
		return true
	}
	// application/x-* covers scripts, installers, etc. not listed above.
	if strings.HasPrefix(ct, "application/x-") {
		return true
	}
	return false
}
