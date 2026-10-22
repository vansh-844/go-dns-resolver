package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

type Server struct {
	Addr           string
	Port           int
	Handler        Handler
	MaxMessages    int
	RequestTimeout int

	mu      sync.Mutex
	conn    net.PacketConn
	started bool
	closing bool
	done    chan struct{} // closed when Start returns
	quit    chan struct{} // closed when Shutdown begins
}

// Bounds for the pause after a failed read, so a persistent error cannot turn
// the read loop into a busy loop.
const (
	minReadBackoff = 5 * time.Millisecond
	maxReadBackoff = time.Second
)

// ServerConfig holds the settings for a Server.
type ServerConfig struct {
	Addr           string
	Port           int
	Handler        Handler
	MaxMessages    int
	RequestTimeout int
}

// NewServer returns a Server built from cfg. It returns ErrNilHandler if
// cfg.Handler is nil.
func NewServer(cfg ServerConfig) (*Server, error) {
	s := &Server{
		Addr:           cfg.Addr,
		Port:           cfg.Port,
		Handler:        cfg.Handler,
		MaxMessages:    cfg.MaxMessages,
		RequestTimeout: cfg.RequestTimeout,
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) validate() error {
	if s.Handler == nil {
		return ErrNilHandler
	}
	return nil
}

// initLocked creates the lifecycle channels if they do not exist yet, so a
// Server works even when it was not built by NewServer. s.mu must be held.
func (s *Server) initLocked() {
	if s.done == nil {
		s.done = make(chan struct{})
		s.quit = make(chan struct{})
	}
}

// nextBackoff returns how long to pause after another failed read.
func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return minReadBackoff
	}
	return min(2*d, maxReadBackoff)
}

const (
	// maxUDPSize is the largest response sent over UDP. Clients that
	// advertise a bigger size with EDNS0 are not given one yet.
	maxUDPSize = 512

	// headerLen is the size of a DNS header. A packet must be at least this
	// long to be worth answering: the reply to a shorter one would be larger
	// than the request.
	headerLen = 12

	qrBit = 0x8000 // the QR flag: set on responses
)

// handlePacket turns one received datagram into the datagram to send back. It
// returns nil when nothing should be sent:
//   - packets shorter than a header, which cannot be answered safely
//   - packets with the QR flag set, which are responses and not queries
//
// Packets that do not parse get FORMERR, handler failures get SERVFAIL, and a
// response over maxUDPSize is replaced by one with the TC flag set and no
// records, so the client retries over TCP.
func (s *Server) handlePacket(ctx context.Context, data []byte) []byte {
	if len(data) < headerLen {
		slog.Warn("dropping packet too short for a DNS header", "bytes", len(data))
		return nil
	}
	id := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&qrBit != 0 {
		slog.Warn("dropping packet that is a response, not a query", "id", id)
		return nil
	}

	query, err := dnsmessage.Unpack(data)
	if err != nil {
		slog.Warn("replying FORMERR to unparseable packet", "id", id, "err", err)
		// Only the header could be read, so that is all the reply echoes.
		bare := &dnsmessage.Message{Header: dnsmessage.Header{ID: id, Flags: flags}}
		return errorReply(bare, dnsmessage.RCodeFormatError)
	}

	response, err := s.Handler.Handle(ctx, query)
	if err != nil {
		slog.Error("handler failed", "id", id, "err", err)
		return errorReply(query, dnsmessage.RCodeServerFailure)
	}
	if response == nil {
		slog.Error("handler returned no response and no error", "id", id)
		return errorReply(query, dnsmessage.RCodeServerFailure)
	}

	packed, err := response.Pack()
	if err != nil {
		slog.Error("packing response failed", "id", id, "err", err)
		return errorReply(query, dnsmessage.RCodeServerFailure)
	}
	if len(packed) > maxUDPSize {
		slog.Debug("truncating oversized response", "id", id, "bytes", len(packed))
		if packed, err = response.Truncate().Pack(); err != nil {
			slog.Error("packing truncated response failed", "id", id, "err", err)
			return errorReply(query, dnsmessage.RCodeServerFailure)
		}
	}
	return packed
}

// errorReply packs a response to query that carries only a response code. It
// returns nil if even that cannot be packed.
func errorReply(query *dnsmessage.Message, rcode dnsmessage.RCode) []byte {
	packed, err := dnsmessage.NewResponse(query, rcode).Pack()
	if err != nil {
		slog.Error("packing error reply failed", "id", query.Header.ID, "rcode", rcode, "err", err)
		return nil
	}
	return packed
}

// Start listens on the configured address and serves requests until Shutdown
// is called. It returns nil after a graceful shutdown, ErrServerClosed if
// Shutdown was called first, and ErrServerStarted if it was already called.
func (s *Server) Start() error {
	if err := s.validate(); err != nil {
		return err
	}

	s.mu.Lock()
	s.initLocked()
	switch {
	case s.closing:
		s.mu.Unlock()
		return ErrServerClosed
	case s.started:
		s.mu.Unlock()
		return ErrServerStarted
	}
	s.started = true
	done, quit := s.done, s.quit
	s.mu.Unlock()
	defer close(done)

	slog.Info("starting server", "addr", s.Addr, "port", s.Port)
	add, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", s.Addr, s.Port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	conn, err := net.ListenPacket("udp", add.String())
	if err != nil {
		return fmt.Errorf("failed to listen on UDP address: %w", err)
	}
	defer conn.Close()

	// Shutdown may have run while the socket was being opened, in which case
	// it found no connection to interrupt.
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.conn = conn
	s.mu.Unlock()

	var backoff time.Duration
	for {
		buffer := make([]byte, 1024)
		n, remoteAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			if s.isClosing() {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("UDP connection closed: %w", err)
			}
			backoff = nextBackoff(backoff)
			slog.Error("reading from UDP connection failed", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-quit:
				return nil
			}
			continue
		}
		backoff = 0

		msg := buffer[:n]
		slog.Debug("received packet", "remote", remoteAddr.String(), "bytes", n)
		if reply := s.handlePacket(context.Background(), msg); len(reply) > 0 {
			if _, err := conn.WriteTo(reply, remoteAddr); err != nil {
				slog.Error("writing response failed", "remote", remoteAddr.String(), "err", err)
			}
		}
		if s.isClosing() {
			return nil
		}
	}
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// Shutdown stops accepting new packets, lets the in-flight request finish, and
// waits for Start to return or ctx to expire. Start returns nil after a
// graceful shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if !s.closing {
		s.closing = true
		close(s.quit)
	}
	conn, done := s.conn, s.done
	s.mu.Unlock()

	if conn == nil {
		return nil
	}
	// Unblock a pending ReadFrom without closing the socket, so a request that
	// is already being handled can still write its response. A closed socket
	// means the server has already stopped.
	if err := conn.SetReadDeadline(time.Now()); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to interrupt read: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		conn.Close()
		return ctx.Err()
	}
}
