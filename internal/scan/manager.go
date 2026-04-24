package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ScanStatus represents the lifecycle state of a scan job.
type ScanStatus int

const (
	StatusPending  ScanStatus = iota
	StatusScanning            // clamd is analysing
	StatusClean               // scan complete, no threat
	StatusInfected            // scan complete, threat found
	StatusError               // clamd unavailable; file buffered, pass-through allowed
	StatusTooLarge            // file exceeded MaxSize mid-scan; incomplete temp file
)

// Job represents a single in-flight or completed scan.
type Job struct {
	ID              string
	Filename        string
	ContentType     string
	ContentEncoding string // e.g. "gzip", "br"; re-applied by ServeFile
	OriginalURL     string
	TempPath        string
	CreatedAt       time.Time

	written    atomic.Int64    // bytes flushed to TempPath so far
	newBytes   chan struct{}   // non-blocking token: new bytes landed in TempPath
	uploadDone chan struct{}   // closed when upstream body is fully written
	resultCh   chan ScanResult // buffered(1); receives exactly one result
	tailBody   io.ReadCloser   // CLI path: remaining body after MaxSize truncation

	mu         sync.RWMutex
	status     ScanStatus
	threatName string
}

// Status returns the current scan status (safe for concurrent use).
func (j *Job) Status() ScanStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.status
}

// ThreatName returns the detected threat name, if any.
func (j *Job) ThreatName() string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.threatName
}

func (j *Job) setResult(s ScanStatus, threat string) {
	j.mu.Lock()
	j.status = s
	j.threatName = threat
	j.mu.Unlock()
}

// Scanner is the interface for virus scanning backends.
// ClamdClient implements this interface; test code can substitute a stub.
type Scanner interface {
	ScanReader(r io.Reader) (ScanResult, error)
}

// Manager owns all active scan jobs and their temp files.
type Manager struct {
	dir     string
	ttl     time.Duration
	maxSize atomic.Int64
	config  atomic.Pointer[ScanConfig]
	clamd   Scanner
	jobs    sync.Map     // map[string]*Job
	cache   *ResultCache // nil = caching disabled
}

// NewManager creates a Manager. dir is the temp file directory. cache may be nil.
func NewManager(dir string, ttl time.Duration, maxSize int64, clamd Scanner, cache *ResultCache) *Manager {
	m := &Manager{dir: dir, ttl: ttl, clamd: clamd, cache: cache}
	m.maxSize.Store(maxSize)
	cfg := DefaultScanConfig()
	cfg.MaxSizeMB = maxSize >> 20
	m.config.Store(cfg)
	return m
}

// MaxSize returns the current max scan size in bytes.
func (m *Manager) MaxSize() int64 { return m.maxSize.Load() }

// Config returns the current ScanConfig.
func (m *Manager) Config() *ScanConfig { return m.config.Load() }

// SetConfig atomically replaces the ScanConfig and updates maxSize.
func (m *Manager) SetConfig(cfg *ScanConfig) {
	m.config.Store(cfg)
	m.maxSize.Store(cfg.MaxSizeBytes())
}

// GetJob retrieves a job by ID.
func (m *Manager) GetJob(id string) (*Job, bool) {
	v, ok := m.jobs.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Job), true
}

// LookupURL returns a cached verdict for the given URL, if any. Used by the
// scan transport to short-circuit before creating a new job and re-fetching
// the body when we already know the answer.
func (m *Manager) LookupURL(ctx context.Context, rawURL string) (ScanStatus, string, bool) {
	if m.cache == nil {
		return 0, "", false
	}
	return m.cache.GetByURL(ctx, rawURL)
}

// NewPresetJob registers a job whose verdict is already known (from the URL
// cache). It has no temp file and no scan goroutine; the scan page's first
// status poll returns the preset verdict immediately. Intended only for
// infected cached URLs — clean ones should bypass the scan page entirely.
func (m *Manager) NewPresetJob(req *http.Request, resp *http.Response, status ScanStatus, threat string) *Job {
	id := newID()
	filename := filenameFrom(req, resp)
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	job := &Job{
		ID:              id,
		Filename:        filename,
		ContentType:     ct,
		ContentEncoding: resp.Header.Get("Content-Encoding"),
		OriginalURL:     req.URL.String(),
		CreatedAt:       time.Now(),
		newBytes:        make(chan struct{}, 1),
		uploadDone:      make(chan struct{}),
		resultCh:        make(chan ScanResult, 1),
		status:          status,
		threatName:      threat,
	}
	close(job.uploadDone)
	m.jobs.Store(id, job)
	return job
}

// StartBrowserJob buffers the upstream response body and scans it in the
// background. The returned *Job can be polled for status via GetJob.
func (m *Manager) StartBrowserJob(req *http.Request, resp *http.Response) *Job {
	job := m.newJob(req, resp)
	go m.runScan(job, resp.Body, false)
	return job
}

// StartCLIJob starts a trickle-mode scan job. The returned TrickleBody should
// be used as the response body sent to the CLI client.
func (m *Manager) StartCLIJob(req *http.Request, resp *http.Response) (*Job, *TrickleBody) {
	job := m.newJob(req, resp)

	f, err := os.Open(job.TempPath)
	if err != nil {
		// Temp file unavailable: skip scan and pass body through directly (Bug 2 fix).
		job.setResult(StatusError, "")
		return job, &TrickleBody{fallback: resp.Body}
	}

	go m.runScan(job, resp.Body, true)
	return job, &TrickleBody{
		job:      job,
		file:     f,
		resultCh: job.resultCh,
	}
}

// runScan reads the upstream body into the temp file while streaming to clamd
// in parallel via io.TeeReader. Updates job status when complete.
// saveTail controls whether a body that exceeds MaxSize is handed to the CLI
// TrickleBody (true) or discarded (false, browser path).
func (m *Manager) runScan(job *Job, body io.ReadCloser, saveTail bool) {
	bodyOwned := true
	defer func() {
		if bodyOwned {
			body.Close()
		}
	}()
	defer close(job.uploadDone)

	f, err := os.OpenFile(job.TempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		job.setResult(StatusError, "")
		job.resultCh <- ScanResult{Clean: true}
		return
	}
	defer f.Close()

	job.setResult(StatusScanning, "")

	// countWriter wraps the file and tracks bytes written for the trickleBody.
	cw := &countWriter{w: f, counter: &job.written, notify: job.newBytes}

	// hw computes SHA-256 of the file content as bytes flow through.
	hw := sha256.New()

	// Writes go to both the temp file (cw) and the hash accumulator (hw).
	fileAndHash := io.MultiWriter(cw, hw)

	// Limit so we never buffer more than MaxSize bytes.
	limited := io.LimitReader(body, m.MaxSize()+1)

	ctx := context.Background()

	// --- URL cache fast path: skip clamd, buffer to disk only ---
	if m.cache != nil {
		if urlStatus, urlThreat, ok := m.cache.GetByURL(ctx, job.OriginalURL); ok {
			tee := io.TeeReader(limited, fileAndHash)
			io.Copy(io.Discard, tee) //nolint:errcheck

			if cw.counter.Load() > m.MaxSize() {
				if saveTail {
					bodyOwned = false
					job.tailBody = body
				} else {
					io.Copy(io.Discard, body) //nolint:errcheck
				}
				job.setResult(StatusTooLarge, "")
				job.resultCh <- ScanResult{Clean: true}
				return
			}

			finalStatus, finalThreat := urlStatus, urlThreat
			if hashStatus, hashThreat, hashOK := m.cache.GetByHash(ctx, hw.Sum(nil)); hashOK {
				finalStatus, finalThreat = mergeResults(urlStatus, urlThreat, hashStatus, hashThreat)
			}

			if finalStatus == StatusClean {
				job.setResult(StatusClean, "")
			} else {
				job.setResult(StatusInfected, finalThreat)
			}
			job.resultCh <- ScanResult{Clean: finalStatus == StatusClean, ThreatName: finalThreat}
			return
		}
	}

	// --- Normal scan path (URL cache miss or cache disabled) ---
	// TeeReader: as ScanReader consumes the stream it also writes to fileAndHash.
	tee := io.TeeReader(limited, fileAndHash)

	result, err := m.clamd.ScanReader(tee)

	// If the stream was truncated (body had more than MaxSize bytes), handle remainder.
	if cw.counter.Load() > m.MaxSize() {
		if saveTail {
			// CLI path: transfer body ownership to TrickleBody so it can chain the
			// remaining bytes after the temp file content for complete delivery.
			bodyOwned = false
			job.tailBody = body
		} else {
			io.Copy(io.Discard, body) //nolint:errcheck
		}
		job.setResult(StatusTooLarge, "")
		job.resultCh <- ScanResult{Clean: true}
		return
	}

	if errors.Is(err, ErrClamdUnavailable) || err != nil {
		slog.Error("scan error", "job", job.ID, "file", job.Filename, "url", job.OriginalURL, "err", err)
		// Drain all remaining bytes into the temp file via tee so that:
		//   - ErrClamdUnavailable (nothing read yet) delivers a complete file to the CLI client
		//   - other errors (partial read) fill the rest, staying within the MaxSize limit via limited
		io.Copy(io.Discard, tee) //nolint:errcheck
		job.setResult(StatusError, "")
		job.resultCh <- ScanResult{Clean: true}
		return
	}

	// hw.Sum(nil) is complete: clamd.ScanReader drove the TeeReader to EOF.
	contentHash := hw.Sum(nil)

	clamdStatus := StatusClean
	if !result.Clean {
		clamdStatus = StatusInfected
	}
	finalStatus, finalThreat := clamdStatus, result.ThreatName

	if m.cache != nil {
		if hashStatus, hashThreat, ok := m.cache.GetByHash(ctx, contentHash); ok {
			finalStatus, finalThreat = mergeResults(clamdStatus, result.ThreatName, hashStatus, hashThreat)
		}
		m.cache.Store(ctx, job.OriginalURL, contentHash, finalStatus, finalThreat)
	}

	if finalStatus == StatusClean {
		job.setResult(StatusClean, "")
	} else {
		job.setResult(StatusInfected, finalThreat)
	}
	job.resultCh <- ScanResult{Clean: finalStatus == StatusClean, ThreatName: finalThreat}
}

// ServeFile serves the buffered temp file to the client.
// Returns false if the job is not in a servable state (not clean or error).
func (m *Manager) ServeFile(job *Job, w http.ResponseWriter, r *http.Request) bool {
	st := job.Status()
	if st != StatusClean && st != StatusError {
		return false
	}
	f, err := os.Open(job.TempPath)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+job.Filename+`"`)
	w.Header().Set("Content-Type", job.ContentType)
	if job.ContentEncoding != "" {
		w.Header().Set("Content-Encoding", job.ContentEncoding)
	}
	http.ServeContent(w, r, job.Filename, info.ModTime(), f)
	return true
}

// StartCleanup launches a background goroutine that removes expired jobs.
// The goroutine exits when ctx is cancelled.
func (m *Manager) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.jobs.Range(func(k, v any) bool {
					job := v.(*Job)
					if time.Since(job.CreatedAt) > m.ttl {
						os.Remove(job.TempPath) //nolint:errcheck
						m.jobs.Delete(k)
					}
					return true
				})
			}
		}
	}()
}

// newJob allocates a Job, creates its (empty) temp file, and stores it.
func (m *Manager) newJob(req *http.Request, resp *http.Response) *Job {
	id := newID()
	filename := filenameFrom(req, resp)
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	tempPath := filepath.Join(m.dir, id)
	// Pre-create so StartCLIJob can open it for reading before the write goroutine starts.
	if f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
		f.Close()
	}
	job := &Job{
		ID:              id,
		Filename:        filename,
		ContentType:     ct,
		ContentEncoding: resp.Header.Get("Content-Encoding"),
		OriginalURL:     req.URL.String(),
		TempPath:        tempPath,
		CreatedAt:       time.Now(),
		newBytes:        make(chan struct{}, 1),
		uploadDone:      make(chan struct{}),
		resultCh:        make(chan ScanResult, 1),
	}
	m.jobs.Store(id, job)
	return job
}

// countWriter wraps an io.Writer and counts bytes written.
type countWriter struct {
	w       io.Writer
	counter *atomic.Int64
	notify  chan<- struct{} // non-blocking signal to waiting readers
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.counter.Add(int64(n))
	select {
	case cw.notify <- struct{}{}:
	default:
	}
	return n, err
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
