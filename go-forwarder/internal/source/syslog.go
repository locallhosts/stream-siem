package source

import (
	"fmt"
	"net"
	"time"
)

// SyslogUDPSource listens for RFC3164/5424-ish syslog datagrams. It does not
// attempt full syslog parsing here on purpose: parsing/enrichment belongs in
// the Flink job so the forwarder stays cheap and stateless. This is the
// standard split used in production log pipelines — collectors ship raw
// bytes, the stream processor owns schema.
type SyslogUDPSource struct {
	ListenAddr   string
	SourceTypeTag string
	NodeID       string

	// ReadBufferBytes bounds the UDP socket receive buffer size requested
	// from the kernel. Under high fan-in (many firewalls), a too-small
	// buffer silently drops datagrams before we ever see them.
	ReadBufferBytes int
}

func (s *SyslogUDPSource) Name() string { return fmt.Sprintf("syslog_udp:%s", s.ListenAddr) }

func (s *SyslogUDPSource) Run(out chan<- Event, errs chan<- error, stop <-chan struct{}) {
	addr, err := net.ResolveUDPAddr("udp", s.ListenAddr)
	if err != nil {
		errs <- fmt.Errorf("%s: resolving addr: %w", s.Name(), err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		errs <- fmt.Errorf("%s: listening: %w", s.Name(), err)
		return
	}
	defer conn.Close()

	bufSize := s.ReadBufferBytes
	if bufSize == 0 {
		bufSize = 8 * 1024 * 1024 // 8MB; generous headroom for bursty firewall log floods
	}
	if err := conn.SetReadBuffer(bufSize); err != nil {
		errs <- fmt.Errorf("%s: setting read buffer: %w", s.Name(), err)
	}

	go func() {
		<-stop
		conn.Close() // unblocks the ReadFromUDP loop below
	}()

	buf := make([]byte, 64*1024) // max practical UDP payload
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-stop:
				return // expected: conn.Close() from the goroutine above
			default:
				errs <- fmt.Errorf("%s: read: %w", s.Name(), err)
				continue
			}
		}
		if n == 0 {
			continue
		}
		line := make([]byte, n)
		copy(line, buf[:n])
		out <- Event{
			SourceType: s.SourceTypeTag,
			Host:       s.NodeID,
			ReceivedAt: time.Now().UTC(),
			Raw:        string(line),
		}
	}
}
