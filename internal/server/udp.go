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

const (
	// Used when the matching ServerConfig field is zero.
	defaultMaxMessages    = 100
	defaultRequestTimeout = 2 * time.Second

	// readBufferSize is the size of the buffer a datagram is read into.
	// Anything larger is cut off, which for DNS queries never matters.
	readBufferSize = 4096

	// Bounds for the pause after a failed read, so a persistent error cannot
	// turn the read loop into a busy loop.
	minReadBackoff = 5 * time.Millisecond
	maxReadBackoff = time.Second
)

// ServerConfig holds the settings for a Server.
type ServerConfig struct {
	// Addr is the address to listen on, as host:port, for example ":8080".
	Addr string

	// Handler answers the queries. It is required.
	Handler Handler

	// MaxMessages is the number of requests handled at the same time. Packets
	// that arrive while that many are in progress are dropped. Zero means 100.
	MaxMessages int

	// RequestTimeout bounds how long a handler may take, through the context
	// it is given. Zero means 2 seconds.
	RequestTimeout time.Duration

	// Logger receives the server's log output. Nil means slog.Default().
	Logger *slog.Logger
}

func (c ServerConfig) maxMessages() int {
	if c.MaxMessages <= 0 {
		return defaultMaxMessages
	}
	return c.MaxMessages
}

func (c ServerConfig) requestTimeout() time.Duration {
	if c.RequestTimeout <= 0 {
		return defaultRequestTimeout
	}
	return c.RequestTimeout
}

// A Server answers DNS queries received over UDP.
//
// Use Start to bind and serve in one call. To learn the bound address before
// serving, call Listen, then Addr, then Serve. Shutdown stops the server.
// A Server can be used only once.
type Server struct {
	cfg ServerConfig

	mu         sync.Mutex
	conn       net.PacketConn
	started    bool // Listen has been called
	serving    bool // Serve has been called
	closing    bool // Shutdown has been called
	finished   bool // done has been closed
	cancelBase context.CancelFunc
	done       chan struct{} // closed when the server has stopped
	quit       chan struct{} // closed when Shutdown begins
}

// NewServer returns a Server built from cfg. It returns ErrNilHandler if
// cfg.Handler is nil.
func NewServer(cfg ServerConfig) (*Server, error) {
	s := &Server{cfg: cfg}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) validate() error {
	if s.cfg.Handler == nil {
		return ErrNilHandler
	}
	return nil
}

func (s *Server) log() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.Default()
}

// initLocked creates the lifecycle channels if they do not exist yet, so a
// Server works even when it was not built by NewServer. s.mu must be held.
func (s *Server) initLocked() {
	if s.done == nil {
		s.done = make(chan struct{})
		s.quit = make(chan struct{})
	}
}

// finishLocked marks the server as stopped, once. s.mu must be held.
func (s *Server) finishLocked() {
	if !s.finished {
		s.finished = true
		close(s.done)
	}
}

func (s *Server) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishLocked()
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

// nextBackoff returns how long to pause after another failed read.
func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return minReadBackoff
	}
	return min(2*d, maxReadBackoff)
}

// Addr returns the address the server is listening on, or nil if Listen has
// not succeeded yet. It is useful when the configured port is 0.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Start binds the configured address and serves requests until Shutdown is
// called. It is Listen followed by Serve.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Listen binds the configured address. It returns ErrNilHandler if there is no
// handler, ErrServerClosed if Shutdown was called first, and ErrServerStarted
// if Listen was already called.
func (s *Server) Listen() error {
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
	s.mu.Unlock()

	conn, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		s.finish()
		return fmt.Errorf("failed to listen on %q: %w", s.cfg.Addr, err)
	}

	// Shutdown may have run while the socket was being opened, in which case
	// it found no connection to close.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		conn.Close()
		s.finishLocked()
		return ErrServerClosed
	}
	s.conn = conn
	return nil
}

// Serve handles requests on the address bound by Listen until Shutdown is
// called, and then returns nil. It returns ErrNotListening if Listen has not
// succeeded, ErrServerClosed if Shutdown was called first, and
// ErrServerStarted if Serve was already called.
//
// Each request runs in its own goroutine, with at most MaxMessages at a time.
func (s *Server) Serve() error {
	s.mu.Lock()
	s.initLocked()
	switch {
	case s.conn == nil:
		s.mu.Unlock()
		return ErrNotListening
	case s.closing:
		s.mu.Unlock()
		return ErrServerClosed
	case s.serving:
		s.mu.Unlock()
		return ErrServerStarted
	}
	s.serving = true
	conn, quit := s.conn, s.quit
	baseCtx, cancel := context.WithCancel(context.Background())
	s.cancelBase = cancel
	s.mu.Unlock()

	var wg sync.WaitGroup
	// Deferred calls run last to first: wait for the requests in flight (which
	// can still reply, as the socket is open), then cancel their context, close
	// the socket, and finally report that the server has stopped.
	defer s.finish()
	defer conn.Close()
	defer cancel()
	defer wg.Wait()

	s.log().Info("serving", "addr", conn.LocalAddr().String())

	slots := make(chan struct{}, s.cfg.maxMessages())
	buffer := make([]byte, readBufferSize)
	var backoff time.Duration
	for {
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			if s.isClosing() {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("UDP connection closed: %w", err)
			}
			backoff = nextBackoff(backoff)
			s.log().Error("reading from UDP connection failed", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-quit:
				return nil
			}
			continue
		}
		backoff = 0
		s.log().Debug("received packet", "remote", remote.String(), "bytes", n)

		select {
		case slots <- struct{}{}:
		default:
			s.log().Warn("dropping packet, too many requests in flight", "remote", remote.String())
			continue
		}

		// The buffer is reused for the next read, so the request gets a copy.
		packet := append([]byte(nil), buffer[:n]...)
		wg.Add(1)
		go func() {
			defer func() {
				<-slots
				wg.Done()
			}()
			s.serveRequest(baseCtx, conn, remote, packet)
		}()
	}
}

// serveRequest answers one packet and writes the reply, if there is one.
func (s *Server) serveRequest(ctx context.Context, conn net.PacketConn, remote net.Addr, packet []byte) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.requestTimeout())
	defer cancel()

	reply := s.handlePacket(ctx, packet)
	if len(reply) == 0 {
		return
	}
	if _, err := conn.WriteTo(reply, remote); err != nil {
		s.log().Error("writing response failed", "remote", remote.String(), "err", err)
	}
}

// Shutdown stops accepting packets, waits for the requests in flight to
// finish, and returns once Serve has returned. If ctx expires first, it cancels
// the context given to the handlers, closes the socket and returns ctx.Err().
// It is safe to call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.initLocked()
	if !s.closing {
		s.closing = true
		close(s.quit)
	}
	conn, done, serving, cancel := s.conn, s.done, s.serving, s.cancelBase
	if conn != nil && !serving {
		// Bound but never served: there is nothing to wait for.
		s.finishLocked()
	}
	s.mu.Unlock()

	if conn == nil {
		return nil
	}
	if !serving {
		conn.Close()
		return nil
	}

	// Unblock a pending read without closing the socket, so requests already
	// being handled can still write their replies. A closed socket means the
	// server has already stopped.
	if err := conn.SetReadDeadline(time.Now()); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("failed to interrupt read: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		if cancel != nil {
			cancel()
		}
		conn.Close()
		return ctx.Err()
	}
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
		s.log().Warn("dropping packet too short for a DNS header", "bytes", len(data))
		return nil
	}
	id := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&qrBit != 0 {
		s.log().Warn("dropping packet that is a response, not a query", "id", id)
		return nil
	}

	query, err := dnsmessage.Unpack(data)
	if err != nil {
		s.log().Warn("replying FORMERR to unparseable packet", "id", id, "err", err)
		// Only the header could be read, so that is all the reply echoes.
		bare := &dnsmessage.Message{Header: dnsmessage.Header{ID: id, Flags: flags}}
		return s.errorReply(bare, dnsmessage.RCodeFormatError)
	}

	response, err := s.cfg.Handler.Handle(ctx, query)
	if err != nil {
		s.log().Error("handler failed", "id", id, "err", err)
		return s.errorReply(query, dnsmessage.RCodeServerFailure)
	}
	if response == nil {
		s.log().Error("handler returned no response and no error", "id", id)
		return s.errorReply(query, dnsmessage.RCodeServerFailure)
	}

	packed, err := response.Pack()
	if err != nil {
		s.log().Error("packing response failed", "id", id, "err", err)
		return s.errorReply(query, dnsmessage.RCodeServerFailure)
	}
	if len(packed) > maxUDPSize {
		s.log().Debug("truncating oversized response", "id", id, "bytes", len(packed))
		if packed, err = response.Truncate().Pack(); err != nil {
			s.log().Error("packing truncated response failed", "id", id, "err", err)
			return s.errorReply(query, dnsmessage.RCodeServerFailure)
		}
	}
	return packed
}

// errorReply packs a response to query that carries only a response code. It
// returns nil if even that cannot be packed.
func (s *Server) errorReply(query *dnsmessage.Message, rcode dnsmessage.RCode) []byte {
	packed, err := dnsmessage.NewResponse(query, rcode).Pack()
	if err != nil {
		s.log().Error("packing error reply failed", "id", query.Header.ID, "rcode", rcode, "err", err)
		return nil
	}
	return packed
}
