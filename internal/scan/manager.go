package scan

import (
	"crypto/rand"
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
)

// Job represents a single in-flight or completed scan.
type Job struct {
	ID          string
	Filename    string
	ContentType string
	OriginalURL string
	TempPath    string
	CreatedAt   time.Time

	written    atomic.Int64    // bytes flushed to TempPath so far
	uploadDone chan struct{}   // closed when upstream body is fully written
	resultCh   chan ScanResult // buffered(1); receives exactly one result

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

// Manager owns all active scan jobs and their temp files.
type Manager struct {
	dir     string
	ttl     time.Duration
	MaxSize int64
	clamd   *ClamdClient
	jobs    sync.Map // map[string]*Job
}

// NewManager creates a Manager. dir is the temp file directory.
func NewManager(dir string, ttl time.Duration, maxSize int64, clamd *ClamdClient) *Manager {
	return &Manager{dir: dir, ttl: ttl, MaxSize: maxSize, clamd: clamd}
}

// GetJob retrieves a job by ID.
func (m *Manager) GetJob(id string) (*Job, bool) {
	v, ok := m.jobs.Load(id)
	if !ok {
		return nil, false
	}
	return v.(*Job), true
}

// StartBrowserJob buffers the upstream response body and scans it in the
// background. The returned *Job can be polled for status via GetJob.
func (m *Manager) StartBrowserJob(req *http.Request, resp *http.Response) *Job {
	job := m.newJob(req, resp)
	go m.runScan(job, resp.Body)
	return job
}

// StartCLIJob starts a trickle-mode scan job. The returned TrickleBody should
// be used as the response body sent to the CLI client.
func (m *Manager) StartCLIJob(req *http.Request, resp *http.Response) (*Job, *TrickleBody) {
	job := m.newJob(req, resp)

	f, err := os.Open(job.TempPath)
	if err != nil {
		// Temp file unavailable: fall back to raw pass-through.
		go m.runScan(job, resp.Body)
		return job, &TrickleBody{fallback: resp.Body}
	}

	go m.runScan(job, resp.Body)
	return job, &TrickleBody{
		job:      job,
		file:     f,
		resultCh: job.resultCh,
	}
}

// runScan reads the upstream body into the temp file while streaming to clamd
// in parallel via io.TeeReader. Updates job status when complete.
func (m *Manager) runScan(job *Job, body io.ReadCloser) {
	defer body.Close()
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
	cw := &countWriter{w: f, counter: &job.written}

	// Limit so we never buffer more than MaxSize bytes.
	limited := io.LimitReader(body, m.MaxSize+1)

	// TeeReader: as ScanReader consumes the stream it also writes to cw (→ file).
	tee := io.TeeReader(limited, cw)

	result, err := m.clamd.ScanReader(tee)

	// If the stream was truncated (body had more than MaxSize bytes), drain the rest.
	if cw.counter.Load() > m.MaxSize {
		io.Copy(io.Discard, body) //nolint:errcheck
		job.setResult(StatusError, "")
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

	if result.Clean {
		job.setResult(StatusClean, "")
	} else {
		job.setResult(StatusInfected, result.ThreatName)
	}
	job.resultCh <- result
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
	http.ServeContent(w, r, job.Filename, info.ModTime(), f)
	return true
}

// StartCleanup launches a background goroutine that removes expired jobs.
func (m *Manager) StartCleanup() {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			m.jobs.Range(func(k, v any) bool {
				job := v.(*Job)
				if time.Since(job.CreatedAt) > m.ttl {
					os.Remove(job.TempPath)
					m.jobs.Delete(k)
				}
				return true
			})
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
		ID:          id,
		Filename:    filename,
		ContentType: ct,
		OriginalURL: req.URL.String(),
		TempPath:    tempPath,
		CreatedAt:   time.Now(),
		uploadDone:  make(chan struct{}),
		resultCh:    make(chan ScanResult, 1),
	}
	m.jobs.Store(id, job)
	return job
}

// countWriter wraps an io.Writer and counts bytes written.
type countWriter struct {
	w       io.Writer
	counter *atomic.Int64
}

func (cw *countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.counter.Add(int64(n))
	return n, err
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

