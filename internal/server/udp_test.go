package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

// noop is a handler that never answers, for tests that send no packets.
func noop(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) { return nil, nil }

// newTestServer returns a server on an OS-chosen port that uses noop.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(ServerConfig{Addr: "127.0.0.1", Handler: HandlerFunc(noop), MaxMessages: 1, RequestTimeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startServer runs s.Start in the background and waits until it has been
// claimed by a Start call, so a second call is guaranteed to be the second.
func startServer(t *testing.T, s *Server) <-chan error {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- s.Start() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			return errc
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func shutdown(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return")
		return nil
	}
}

func TestNewServerNilHandler(t *testing.T) {
	if _, err := NewServer(ServerConfig{Addr: "127.0.0.1"}); !errors.Is(err, ErrNilHandler) {
		t.Errorf("err = %v, want ErrNilHandler", err)
	}
}

func TestStartNilHandler(t *testing.T) {
	s := &Server{Addr: "127.0.0.1"}
	if err := s.Start(); !errors.Is(err, ErrNilHandler) {
		t.Errorf("err = %v, want ErrNilHandler", err)
	}
}

func TestStartTwice(t *testing.T) {
	s := newTestServer(t)
	errc := startServer(t, s)

	if err := s.Start(); !errors.Is(err, ErrServerStarted) {
		t.Errorf("second Start = %v, want ErrServerStarted", err)
	}
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("first Start = %v, want nil", err)
	}

	// A stopped server cannot be started again either.
	if err := s.Start(); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Start after Shutdown = %v, want ErrServerClosed", err)
	}
}

func TestShutdownBeforeStart(t *testing.T) {
	s := newTestServer(t)
	shutdown(t, s)
	if err := s.Start(); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Start = %v, want ErrServerClosed", err)
	}
}

func TestShutdownTwice(t *testing.T) {
	s := newTestServer(t)
	errc := startServer(t, s)
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("Start = %v, want nil", err)
	}
	shutdown(t, s) // must not fail, panic or block on an already stopped server
}

func TestZeroValueServer(t *testing.T) {
	s := &Server{Addr: "127.0.0.1", Handler: HandlerFunc(noop)}
	errc := startServer(t, s)
	shutdown(t, s)
	if err := waitFor(t, errc); err != nil {
		t.Errorf("Start = %v, want nil", err)
	}

	// Shutdown on a zero-value server that never started must not panic.
	shutdown(t, &Server{})
}

func TestStartFailsOnBadAddress(t *testing.T) {
	s := &Server{Addr: "256.256.256.256", Handler: HandlerFunc(noop)}
	if err := s.Start(); err == nil {
		t.Fatal("Start succeeded on an invalid address")
	}
	// The failed Start must still release anyone waiting on the server.
	shutdown(t, s)
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
