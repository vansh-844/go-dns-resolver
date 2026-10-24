package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const testWait = 2 * time.Second

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// noop is a handler that never answers, for tests that send no packets.
func noop(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) { return nil, nil }

// testConfig returns a config that listens on a port chosen by the OS and
// stays quiet.
func testConfig(h Handler) ServerConfig {
	return ServerConfig{Addr: "127.0.0.1:0", Handler: h, Logger: quietLogger}
}

func newTestServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// waitServing blocks until a Serve call has claimed the server, so that a
// Shutdown or a second Serve afterwards is guaranteed to come after it.
func waitServing(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for {
		s.mu.Lock()
		serving := s.serving
		s.mu.Unlock()
		if serving {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start serving")
		}
		time.Sleep(time.Millisecond)
	}
}

// runServer listens, serves in the background, and arranges for the server to
// be stopped when the test ends. It returns the address to send queries to.
func runServer(t *testing.T, s *Server) (addr string, serveErr <-chan error) {
	t.Helper()
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Serve() }()
	waitServing(t, s)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s.Addr().String(), errc
}

func shutdown(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func waitFor(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(testWait):
		t.Fatal("Serve did not return")
		return nil
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// readReply reads one datagram from c, or returns nil if none arrives in d.
func readReply(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil
		}
		t.Fatal(err)
	}
	return buf[:n]
}

// exchange sends data and returns the reply, failing if there is none.
func exchange(t *testing.T, addr string, data []byte) []byte {
	t.Helper()
	c := dial(t, addr)
	if _, err := c.Write(data); err != nil {
		t.Fatal(err)
	}
	reply := readReply(t, c, testWait)
	if reply == nil {
		t.Fatal("no reply")
	}
	return reply
}

func staticHandler(t *testing.T) Handler {
	t.Helper()
	h, err := NewStaticHandler(netip.MustParseAddr("192.0.2.7"), 60)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// ---- lifecycle ----

func TestNewServerNilHandler(t *testing.T) {
	if _, err := NewServer(ServerConfig{Addr: "127.0.0.1:0"}); !errors.Is(err, ErrNilHandler) {
		t.Errorf("err = %v, want ErrNilHandler", err)
	}
}

func TestListenAndStartNilHandler(t *testing.T) {
	s := &Server{}
	if err := s.Listen(); !errors.Is(err, ErrNilHandler) {
		t.Errorf("Listen = %v, want ErrNilHandler", err)
	}
	if err := s.Start(); !errors.Is(err, ErrNilHandler) {
		t.Errorf("Start = %v, want ErrNilHandler", err)
	}
}

func TestAddr(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	if s.Addr() != nil {
		t.Errorf("Addr before Listen = %v, want nil", s.Addr())
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	defer shutdown(t, s)
	udp, ok := s.Addr().(*net.UDPAddr)
	if !ok || udp.Port == 0 {
		t.Errorf("Addr = %v, want a UDP address with a real port", s.Addr())
	}
}

func TestListenTwice(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	defer shutdown(t, s)
	if err := s.Listen(); !errors.Is(err, ErrServerStarted) {
		t.Errorf("second Listen = %v, want ErrServerStarted", err)
	}
}

func TestServeTwice(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	_, errc := runServer(t, s)

	if err := s.Serve(); !errors.Is(err, ErrServerStarted) {
		t.Errorf("second Serve = %v, want ErrServerStarted", err)
	}
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("first Serve = %v, want nil", err)
	}
}

func TestServeWithoutListen(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	if err := s.Serve(); !errors.Is(err, ErrNotListening) {
		t.Errorf("Serve = %v, want ErrNotListening", err)
	}
}

func TestStartThenShutdown(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	errc := make(chan error, 1)
	go func() { errc <- s.Start() }()

	waitServing(t, s)
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("Start = %v, want nil", err)
	}
	if err := s.Start(); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Start after Shutdown = %v, want ErrServerClosed", err)
	}
}

func TestShutdownBeforeStart(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	shutdown(t, s)
	if err := s.Start(); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Start = %v, want ErrServerClosed", err)
	}
}

func TestShutdownTwice(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	_, errc := runServer(t, s)
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("Serve = %v, want nil", err)
	}
	shutdown(t, s) // must not fail, panic or block on an already stopped server
}

func TestShutdownAfterListenWithoutServe(t *testing.T) {
	s := newTestServer(t, testConfig(HandlerFunc(noop)))
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	shutdown(t, s)
	if err := s.Serve(); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve after Shutdown = %v, want ErrServerClosed", err)
	}
}

func TestZeroValueServer(t *testing.T) {
	s := &Server{cfg: testConfig(HandlerFunc(noop))}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Serve() }()
	waitServing(t, s)
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("Serve = %v, want nil", err)
	}

	// Shutdown on a zero-value server that never started must not panic.
	shutdown(t, &Server{})
}

func TestListenFailsOnBadAddress(t *testing.T) {
	cfg := testConfig(HandlerFunc(noop))
	cfg.Addr = "256.256.256.256:0"
	s := newTestServer(t, cfg)
	if err := s.Listen(); err == nil {
		t.Fatal("Listen succeeded on an invalid address")
	}
	// The failed Listen must still release anyone waiting on the server.
	shutdown(t, s)
}

func TestListenFailsWhenPortIsTaken(t *testing.T) {
	first := newTestServer(t, testConfig(HandlerFunc(noop)))
	if err := first.Listen(); err != nil {
		t.Fatal(err)
	}
	defer shutdown(t, first)

	cfg := testConfig(HandlerFunc(noop))
	cfg.Addr = first.Addr().String()
	second := newTestServer(t, cfg)
	if err := second.Listen(); err == nil {
		t.Fatal("Listen succeeded on a port that is in use")
	}
}

func TestNextBackoff(t *testing.T) {
	d := time.Duration(0)
	var got []time.Duration
	for i := 0; i < 12; i++ {
		d = nextBackoff(d)
		got = append(got, d)
	}
	if got[0] != minReadBackoff {
		t.Errorf("first backoff = %v, want %v", got[0], minReadBackoff)
	}
	if got[1] != 2*minReadBackoff {
		t.Errorf("second backoff = %v, want %v", got[1], 2*minReadBackoff)
	}
	if last := got[len(got)-1]; last != maxReadBackoff {
		t.Errorf("backoff did not cap: %v, want %v", last, maxReadBackoff)
	}
}

func TestConfigDefaults(t *testing.T) {
	var c ServerConfig
	if c.maxMessages() != defaultMaxMessages || c.requestTimeout() != defaultRequestTimeout {
		t.Errorf("defaults = %d, %v", c.maxMessages(), c.requestTimeout())
	}
	c = ServerConfig{MaxMessages: 3, RequestTimeout: time.Second}
	if c.maxMessages() != 3 || c.requestTimeout() != time.Second {
		t.Errorf("explicit values not used: %d, %v", c.maxMessages(), c.requestTimeout())
	}
}

// ---- over a real socket ----

func TestServerAnswersQuery(t *testing.T) {
	s := newTestServer(t, testConfig(staticHandler(t)))
	addr, _ := runServer(t, s)

	reply := exchange(t, addr, queryBytes(t, 0x4242, flagRD, question("example.com", dnsmessage.TypeA)))
	m := mustUnpack(t, reply)
	if m.Header.ID != 0x4242 || !m.Header.IsResponse() || m.Header.RCode() != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v", m.Header)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %+v", m.Answers)
	}
	if a, ok := m.Answers[0].Data.(dnsmessage.A); !ok || a.Addr != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("answer = %+v", m.Answers[0])
	}
}

func TestServerFormErr(t *testing.T) {
	s := newTestServer(t, testConfig(staticHandler(t)))
	addr, _ := runServer(t, s)

	garbage := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	m := mustUnpack(t, exchange(t, addr, garbage))
	if m.Header.ID != 0xabcd || m.Header.RCode() != dnsmessage.RCodeFormatError {
		t.Errorf("header = %+v", m.Header)
	}
}

func TestServerServFail(t *testing.T) {
	failing := HandlerFunc(func(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) {
		return nil, errors.New("boom")
	})
	s := newTestServer(t, testConfig(failing))
	addr, _ := runServer(t, s)

	m := mustUnpack(t, exchange(t, addr, queryBytes(t, 9, flagRD, question("example.com", dnsmessage.TypeA))))
	if m.Header.ID != 9 || m.Header.RCode() != dnsmessage.RCodeServerFailure {
		t.Errorf("header = %+v", m.Header)
	}
}

func TestServerStaysSilent(t *testing.T) {
	s := newTestServer(t, testConfig(staticHandler(t)))
	addr, _ := runServer(t, s)

	query := queryBytes(t, 1, flagRD, question("example.com", dnsmessage.TypeA))
	response := append([]byte(nil), query...)
	response[2] |= 0x80

	for name, data := range map[string][]byte{
		"one byte":     {1},
		"short packet": query[:headerLen-1],
		"a response":   response,
	} {
		t.Run(name, func(t *testing.T) {
			c := dial(t, addr)
			if _, err := c.Write(data); err != nil {
				t.Fatal(err)
			}
			if reply := readReply(t, c, 150*time.Millisecond); reply != nil {
				t.Errorf("got reply % x, want none", reply)
			}
		})
	}

	// The server must still be healthy afterwards.
	m := mustUnpack(t, exchange(t, addr, query))
	if m.Header.RCode() != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v", m.Header)
	}
}

func TestServerManyClientsGetTheirOwnReplies(t *testing.T) {
	s := newTestServer(t, testConfig(staticHandler(t)))
	addr, _ := runServer(t, s)

	const clients = 50
	errc := make(chan error, clients)
	for i := 0; i < clients; i++ {
		go func() {
			id := uint16(1000 + i)
			c, err := net.Dial("udp", addr)
			if err != nil {
				errc <- err
				return
			}
			defer c.Close()
			wire, err := newQuery(id, flagRD, question("example.com", dnsmessage.TypeA)).Pack()
			if err != nil {
				errc <- err
				return
			}
			if _, err := c.Write(wire); err != nil {
				errc <- err
				return
			}
			c.SetReadDeadline(time.Now().Add(testWait))
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			m, err := dnsmessage.Unpack(buf[:n])
			if err != nil {
				errc <- err
				return
			}
			if m.Header.ID != id {
				errc <- errors.New("reply carries another client's ID")
				return
			}
			errc <- nil
		}()
	}
	for i := 0; i < clients; i++ {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
}

// ---- concurrency ----

// gate is a handler that reports each arrival and then blocks until released
// or until its context is done.
type gate struct {
	arrived chan struct{}
	release chan struct{}
	ctxErr  chan error
}

func newGate() *gate {
	return &gate{
		arrived: make(chan struct{}, 16),
		release: make(chan struct{}),
		ctxErr:  make(chan error, 16),
	}
}

func (g *gate) Handle(ctx context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
	g.arrived <- struct{}{}
	select {
	case <-g.release:
		return dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess), nil
	case <-ctx.Done():
		g.ctxErr <- ctx.Err()
		return nil, ctx.Err()
	}
}

func (g *gate) waitArrivals(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.arrived:
		case <-time.After(testWait):
			t.Fatalf("only %d of %d requests reached the handler", i, n)
		}
	}
}

func sendQuery(t *testing.T, addr string, id uint16) net.Conn {
	t.Helper()
	c := dial(t, addr)
	if _, err := c.Write(queryBytes(t, id, flagRD, question("example.com", dnsmessage.TypeA))); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRequestsRunConcurrently(t *testing.T) {
	g := newGate()
	s := newTestServer(t, testConfig(g))
	addr, _ := runServer(t, s)

	c1 := sendQuery(t, addr, 1)
	c2 := sendQuery(t, addr, 2)
	g.waitArrivals(t, 2) // would time out if requests were handled one at a time
	close(g.release)

	for i, c := range []net.Conn{c1, c2} {
		if reply := readReply(t, c, testWait); reply == nil {
			t.Errorf("client %d got no reply", i+1)
		}
	}
}

func TestRequestTimeout(t *testing.T) {
	g := newGate() // never released: only the timeout can end the request
	cfg := testConfig(g)
	cfg.RequestTimeout = 50 * time.Millisecond
	s := newTestServer(t, cfg)
	addr, _ := runServer(t, s)

	c := sendQuery(t, addr, 7)
	reply := readReply(t, c, testWait)
	if reply == nil {
		t.Fatal("no reply after the timeout")
	}
	m := mustUnpack(t, reply)
	if m.Header.ID != 7 || m.Header.RCode() != dnsmessage.RCodeServerFailure {
		t.Errorf("header = %+v, want SERVFAIL", m.Header)
	}
	select {
	case err := <-g.ctxErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("handler context error = %v, want DeadlineExceeded", err)
		}
	default:
		t.Error("handler never saw its context expire")
	}
}

func TestExcessRequestsAreDropped(t *testing.T) {
	g := newGate()
	cfg := testConfig(g)
	cfg.MaxMessages = 1
	s := newTestServer(t, cfg)
	addr, _ := runServer(t, s)

	c1 := sendQuery(t, addr, 1)
	g.waitArrivals(t, 1)
	c2 := sendQuery(t, addr, 2) // no free slot: dropped
	if reply := readReply(t, c2, 150*time.Millisecond); reply != nil {
		t.Errorf("dropped request got a reply: % x", reply)
	}

	close(g.release)
	if reply := readReply(t, c1, testWait); reply == nil {
		t.Error("the request being handled got no reply")
	}
	if reply := readReply(t, c2, 150*time.Millisecond); reply != nil {
		t.Errorf("dropped request got a late reply: % x", reply)
	}

	// The slot is free again.
	c3 := sendQuery(t, addr, 3)
	if reply := readReply(t, c3, testWait); reply == nil {
		t.Error("no reply once the slot was free")
	}
}

func TestShutdownWaitsForRequestsInFlight(t *testing.T) {
	g := newGate()
	s := newTestServer(t, testConfig(g))
	addr, serveErr := runServer(t, s)

	c := sendQuery(t, addr, 1)
	g.waitArrivals(t, 1)

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), testWait)
		defer cancel()
		shutdownErr <- s.Shutdown(ctx)
	}()

	select {
	case err := <-shutdownErr:
		t.Fatalf("Shutdown returned (%v) while a request was in flight", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(g.release)
	if reply := readReply(t, c, testWait); reply == nil {
		t.Error("the in-flight request got no reply during shutdown")
	}
	select {
	case err := <-shutdownErr:
		if err != nil {
			t.Errorf("Shutdown = %v, want nil", err)
		}
	case <-time.After(testWait):
		t.Fatal("Shutdown did not return after the request finished")
	}
	if err := waitFor(t, serveErr); err != nil {
		t.Errorf("Serve = %v, want nil", err)
	}
}

func TestForcedShutdownCancelsHandlers(t *testing.T) {
	g := newGate()
	cfg := testConfig(g)
	cfg.RequestTimeout = time.Minute // so only the shutdown can cancel
	s := newTestServer(t, cfg)
	addr, serveErr := runServer(t, s)

	sendQuery(t, addr, 1)
	g.waitArrivals(t, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want DeadlineExceeded", err)
	}

	select {
	case err := <-g.ctxErr:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("handler context error = %v, want Canceled", err)
		}
	case <-time.After(testWait):
		t.Fatal("handler context was not cancelled")
	}
	waitFor(t, serveErr)
}
