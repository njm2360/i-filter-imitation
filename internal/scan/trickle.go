package scan

import (
	"errors"
	"io"
	"os"
	"time"
)

// TrickleBody is an io.ReadCloser that trickles buffered file content at ~1 B/s
// until the scan result is known, then either flushes (clean) or aborts (infected).
type TrickleBody struct {
	job      *Job
	file     *os.File
	resultCh <-chan ScanResult
	readPos  int64
	mode     trickleMode
	fallback io.ReadCloser // set when temp file could not be opened
}

type trickleMode int

const (
	modeTrickling trickleMode = iota
	modeFlushing
	modeAborted
)

var errVirusDetected = errors.New("connection closed: virus detected")

func (b *TrickleBody) Read(p []byte) (int, error) {
	if b.fallback != nil {
		return b.fallback.Read(p)
	}
	switch b.mode {
	case modeAborted:
		return 0, errVirusDetected
	case modeFlushing:
		return b.flushRead(p)
	default: // modeTrickling
		timer := time.NewTimer(time.Second)
		select {
		case res := <-b.resultCh:
			timer.Stop()
			if res.Clean {
				b.mode = modeFlushing
				return b.flushRead(p)
			}
			b.mode = modeAborted
			return 0, errVirusDetected
		case <-timer.C:
			return b.readOne(p)
		}
	}
}

func (b *TrickleBody) Close() error {
	var err error
	if b.file != nil {
		err = b.file.Close()
	}
	if b.job != nil {
		if tail := b.job.tailBody; tail != nil {
			tail.Close() //nolint:errcheck
		}
	}
	if b.fallback != nil {
		err = b.fallback.Close()
	}
	return err
}

// readOne reads exactly one byte from the temp file, spinning until data is available.
func (b *TrickleBody) readOne(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if b.readPos < b.job.written.Load() {
			n, err := b.file.ReadAt(p[:1], b.readPos)
			if n > 0 {
				b.readPos++
			}
			return n, err
		}
		select {
		case <-b.job.uploadDone:
			if b.readPos >= b.job.written.Load() {
				if tail := b.job.tailBody; tail != nil {
					return tail.Read(p[:1])
				}
				return 0, io.EOF
			}
		case <-b.job.newBytes:
		}
	}
}

// flushRead reads as many available bytes as possible, returning io.EOF when
// the upload goroutine is done and all bytes have been consumed.
func (b *TrickleBody) flushRead(p []byte) (int, error) {
	for {
		available := b.job.written.Load() - b.readPos
		if available > 0 {
			toRead := min(int64(len(p)), available)
			n, err := b.file.ReadAt(p[:toRead], b.readPos)
			if n > 0 {
				b.readPos += int64(n)
				return n, nil
			}
			if err != nil && err != io.EOF {
				return 0, err
			}
		}
		select {
		case <-b.job.uploadDone:
			if b.readPos >= b.job.written.Load() {
				if tail := b.job.tailBody; tail != nil {
					return tail.Read(p)
				}
				return 0, io.EOF
			}
		case <-b.job.newBytes:
		}
	}
}
