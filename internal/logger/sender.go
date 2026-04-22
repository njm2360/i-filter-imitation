package logger

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Sender asynchronously forwards AccessRecords as RFC 5424 syslog messages.
type Sender struct {
	network  string
	raddr    string
	hostname string
	appName  string
	procID   string
	ch       chan AccessRecord
	stop     chan struct{}
	wg       sync.WaitGroup
}

// NewSender creates a Sender and starts the background drain goroutine.
// bufSize controls how many records can queue before Send() drops.
func NewSender(network, raddr string, bufSize int) *Sender {
	hostname, _ := os.Hostname()
	s := &Sender{
		network:  network,
		raddr:    raddr,
		hostname: hostname,
		appName:  "log-proxy",
		procID:   fmt.Sprintf("%d", os.Getpid()),
		ch:       make(chan AccessRecord, bufSize),
		stop:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.drain()
	return s
}

// Send enqueues a record. Non-blocking; drops if channel is full.
func (s *Sender) Send(r AccessRecord) {
	select {
	case s.ch <- r:
	default:
		slog.Warn("syslog sender buffer full, dropping record", "host", r.Host)
	}
}

// Close signals shutdown and waits for the drain goroutine to flush remaining records.
func (s *Sender) Close() {
	close(s.stop)
	s.wg.Wait()
}

func (s *Sender) drain() {
	defer s.wg.Done()

	var conn net.Conn
	connect := func() {
		var err error
		conn, err = net.DialTimeout(s.network, s.raddr, 5*time.Second)
		if err != nil {
			slog.Warn("syslog dial failed", "addr", s.raddr, "err", err)
			conn = nil
		}
	}
	connect()

	write := func(r AccessRecord) {
		msg := append(Format5424(r, s.hostname, s.appName, s.procID), '\n')
		if conn == nil {
			connect()
		}
		if conn != nil {
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(msg); err != nil {
				slog.Warn("syslog write failed, reconnecting", "err", err)
				conn.Close()
				conn = nil
			}
		}
	}

	for {
		select {
		case r := <-s.ch:
			write(r)
		case <-s.stop:
			// flush remaining queued records before exit
			for {
				select {
				case r := <-s.ch:
					write(r)
				default:
					if conn != nil {
						conn.Close()
					}
					return
				}
			}
		}
	}
}
