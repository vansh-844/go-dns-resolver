// Package forward answers DNS queries by passing them on to upstream
// resolvers, such as 1.1.1.1, and returning what they reply.
//
// A Forwarder satisfies server.Handler without importing the server package:
// Go interfaces are satisfied by having the right methods.
package forward

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	// defaultTimeout is used when Config.Timeout is zero.
	defaultTimeout = time.Second

	// maxDatagramSize is the largest possible UDP payload. Replies are read
	// into a buffer this big, since a smaller one silently cuts off a larger
	// datagram.
	maxDatagramSize = 65535

	// headerLen is the size of a DNS header.
	headerLen = 12
)

// Config holds the settings for a Forwarder.
type Config struct {
	// Upstreams are the resolvers to ask, as host:port, for example
	// "1.1.1.1:53". They are tried in order until one answers. Required.
	Upstreams []string

	// Timeout bounds how long to wait for each upstream. The context given to
	// Handle can cut it shorter. Zero means 1 second.
	Timeout time.Duration

	// Logger receives the forwarder's log output. Nil means slog.Default().
	Logger *slog.Logger
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return defaultTimeout
	}
	return c.Timeout
}

// A Forwarder answers queries by asking upstream resolvers. It is safe for
// use by many goroutines at once.
type Forwarder struct {
	cfg Config

	// newID returns the ID for an upstream query. Tests replace it to get a
	// known ID.
	newID func() uint16
}

// New returns a Forwarder built from cfg. It returns ErrNoUpstreams if there
// are no upstreams and ErrBadUpstream if one is not a host:port address.
func New(cfg Config) (*Forwarder, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, ErrNoUpstreams
	}
	for _, u := range cfg.Upstreams {
		host, port, err := net.SplitHostPort(u)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrBadUpstream, u, err)
		}
		if host == "" || port == "" {
			return nil, fmt.Errorf("%w %q: host and port are both required", ErrBadUpstream, u)
		}
	}
	// Copy, so that the caller changing its slice later does not affect us.
	cfg.Upstreams = slices.Clone(cfg.Upstreams)
	return &Forwarder{cfg: cfg, newID: randomID}, nil
}

// randomID returns an unpredictable query ID. An off-path attacker who can
// guess the ID (and the source port) can forge a reply that is accepted, so
// it comes from crypto/rand rather than math/rand.
func randomID() uint16 {
	var b [2]byte
	rand.Read(b[:]) // never fails, as of Go 1.24
	return binary.BigEndian.Uint16(b[:])
}

func (f *Forwarder) log() *slog.Logger {
	if f.cfg.Logger != nil {
		return f.cfg.Logger
	}
	return slog.Default()
}

// Handle implements server.Handler. It sends the query to each upstream in
// turn and returns the first matching reply, with the query's ID. Its rcode
// and flags are passed on unchanged, NXDOMAIN and SERVFAIL included.
//
// The upstream query has no records, so EDNS is not used: the upstream keeps
// its reply within 512 bytes, or sets the TC flag.
//
// It returns an error wrapping ErrNoAnswer if no upstream answers in time.
func (f *Forwarder) Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	if len(query.Questions) != 1 {
		return dnsmessage.NewResponse(query, dnsmessage.RCodeFormatError), nil
	}
	q := query.Questions[0]

	// A new message, so query itself is left as the server gave it.
	id := f.newID()
	upstreamQuery := &dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Flags: query.Header.Flags},
		Questions: []dnsmessage.Question{q},
	}
	wire, err := upstreamQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("forward: packing query: %w", err)
	}

	var errs []error
	for _, upstream := range f.cfg.Upstreams {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		reply, err := f.exchange(ctx, upstream, wire, id, q)
		if err != nil {
			f.log().Debug("upstream failed", "upstream", upstream, "name", q.Name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", upstream, err))
			continue
		}
		reply.Header.ID = query.Header.ID
		return reply, nil
	}
	return nil, fmt.Errorf("%w for %s %s: %w", ErrNoAnswer, q.Name, q.Type, errors.Join(errs...))
}

// exchange sends one query to upstream and waits for the matching reply.
func (f *Forwarder) exchange(ctx context.Context, upstream string, wire []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	// A connected socket: the kernel drops datagrams from any other address,
	// and each new socket gets a new random source port.
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Closing the socket makes a blocked Read return at once, so a cancelled
	// request (for example on shutdown) stops waiting.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	deadline := time.Now().Add(f.cfg.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(wire); err != nil {
		return nil, preferCtxErr(ctx, err)
	}

	buf := make([]byte, maxDatagramSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, preferCtxErr(ctx, err)
		}
		reply, err := checkReply(buf[:n], id, q)
		if err != nil {
			f.log().Debug("ignoring datagram from upstream", "upstream", upstream, "bytes", n, "reason", err)
			continue
		}
		return reply, nil
	}
}

// checkReply parses b and reports whether it is the reply to the query with
// the given ID and question.
func checkReply(b []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	if len(b) < headerLen {
		return nil, errShortReply
	}
	// Checked before parsing, as it is cheap and rules out most stray packets.
	if binary.BigEndian.Uint16(b[0:2]) != id {
		return nil, errWrongID
	}
	m, err := dnsmessage.Unpack(b)
	if err != nil {
		return nil, err
	}
	if !m.Header.IsResponse() {
		return nil, errNotResponse
	}
	if len(m.Questions) != 1 {
		return nil, errWrongQuestion
	}
	// Names compare without regard to case (RFC 4343); some resolvers
	// randomise the case of queries as an extra check.
	got := m.Questions[0]
	if !strings.EqualFold(got.Name, q.Name) || got.Type != q.Type || got.Class != q.Class {
		return nil, errWrongQuestion
	}
	return m, nil
}

// preferCtxErr returns ctx's error if ctx is done, since that is the real
// reason a read or write failed after AfterFunc closed the socket.
func preferCtxErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
