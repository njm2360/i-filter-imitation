package scan

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ErrClamdUnavailable is returned when clamd cannot be reached.
var ErrClamdUnavailable = errors.New("clamd unavailable")

// ScanResult holds the outcome of a ClamAV scan.
type ScanResult struct {
	Clean      bool
	ThreatName string
}

// ClamdClient communicates with clamd via the INSTREAM protocol.
type ClamdClient struct {
	network string
	address string
	timeout time.Duration
}

// NewClamdClient creates a client. network is "unix" or "tcp"; address is a
// socket path or "host:port".
func NewClamdClient(network, address string, timeout time.Duration) *ClamdClient {
	return &ClamdClient{network: network, address: address, timeout: timeout}
}

// ScanReader streams r to clamd using the INSTREAM protocol and returns the
// scan result. Returns ErrClamdUnavailable if the connection fails.
func (c *ClamdClient) ScanReader(r io.Reader) (ScanResult, error) {
	conn, err := net.DialTimeout(c.network, c.address, c.timeout)
	if err != nil {
		return ScanResult{}, ErrClamdUnavailable
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if _, err := conn.Write([]byte("nINSTREAM\n")); err != nil {
		return ScanResult{}, fmt.Errorf("clamd write command: %w", err)
	}

	if err := streamToClamd(conn, r); err != nil {
		return ScanResult{}, fmt.Errorf("clamd stream: %w", err)
	}

	return readClamdResult(conn)
}

// streamToClamd sends data from r to conn using the INSTREAM chunk protocol.
func streamToClamd(conn net.Conn, r io.Reader) error {
	buf := make([]byte, 4096)
	var lenBuf [4]byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
			if _, werr := conn.Write(lenBuf[:]); werr != nil {
				return werr
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	// Send zero-length chunk to signal EOF.
	binary.BigEndian.PutUint32(lenBuf[:], 0)
	_, err := conn.Write(lenBuf[:])
	return err
}

// readClamdResult reads and parses the one-line response from clamd.
func readClamdResult(conn net.Conn) (ScanResult, error) {
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return ScanResult{}, fmt.Errorf("clamd read response: %w", err)
		}
		return ScanResult{}, fmt.Errorf("clamd returned empty response")
	}
	line := scanner.Text()

	// "stream: OK" → clean
	if line == "stream: OK" {
		return ScanResult{Clean: true}, nil
	}
	// "stream: <ThreatName> FOUND"
	if strings.HasSuffix(line, " FOUND") {
		threat := strings.TrimPrefix(line, "stream: ")
		threat = strings.TrimSuffix(threat, " FOUND")
		return ScanResult{Clean: false, ThreatName: threat}, nil
	}
	return ScanResult{}, fmt.Errorf("unexpected clamd response: %q", line)
}
