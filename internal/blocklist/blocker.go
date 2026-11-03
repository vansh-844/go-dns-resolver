package blocklist

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	// defaultTTL is used when Config.TTL is zero. It is short, so that a
	// domain removed from the list works again soon.
	defaultTTL = 10

	flagRA uint16 = 0x0080 // recursion available
)

// Handler is what the blocker wraps. It has the same method as
// server.Handler, so a cache or a forwarder fits it, and a *Blocker can be
// given to the server.
type Handler interface {
	Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error)
}

// Mode is how blocked queries are answered.
type Mode int

const (
	// ModeNull answers A queries with 0.0.0.0 and AAAA queries with ::, and
	// other types with no records, all with NOERROR. Clients then fail at
	// once instead of retrying, which is what Pi-hole does by default.
	ModeNull Mode = iota

	// ModeNXDOMAIN answers that the name does not exist.
	ModeNXDOMAIN
)

// ParseMode turns "null" or "nxdomain" into a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "null":
		return ModeNull, nil
	case "nxdomain":
		return ModeNXDOMAIN, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrBadMode, s)
}

// Config holds the settings for a Blocker.
type Config struct {
	// Mode is how blocked queries are answered. The zero value is ModeNull.
	Mode Mode

	// TTL is the TTL in seconds of the records in blocked answers. Zero
	// means 10.
	TTL uint32

	// Logger receives a Debug line for each blocked query. Nil means
	// slog.Default().
	Logger *slog.Logger
}

func (c Config) ttl() uint32 {
	if c.TTL == 0 {
		return defaultTTL
	}
	return c.TTL
}

// A Blocker answers queries for listed domains itself and passes all other
// queries on. It is safe for use by many goroutines at once, including while
// the list is replaced with SetList.
type Blocker struct {
	next Handler
	cfg  Config

	// list is replaced as a whole, never modified, so readers need no lock:
	// each query sees either the old list or the new one.
	list atomic.Pointer[List]
}

// New returns a Blocker that checks queries against list before passing them
// to next.
func New(next Handler, list *List, cfg Config) (*Blocker, error) {
	if next == nil {
		return nil, ErrNilHandler
	}
	if list == nil {
		return nil, ErrNilList
	}
	b := &Blocker{next: next, cfg: cfg}
	b.list.Store(list)
	return b, nil
}

// SetList replaces the list, for example after the files were updated.
// Queries already being handled finish with the old list.
func (b *Blocker) SetList(list *List) error {
	if list == nil {
		return ErrNilList
	}
	b.list.Store(list)
	return nil
}

// List returns the list in use.
func (b *Blocker) List() *List { return b.list.Load() }

func (b *Blocker) log() *slog.Logger {
	if b.cfg.Logger != nil {
		return b.cfg.Logger
	}
	return slog.Default()
}

// Handle implements server.Handler. Only queries with exactly one question
// in class IN are checked; all others are passed on.
func (b *Blocker) Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	if len(query.Questions) != 1 || query.Questions[0].Class != dnsmessage.ClassIN {
		return b.next.Handle(ctx, query)
	}
	q := query.Questions[0]
	if !b.list.Load().Blocked(q.Name) {
		return b.next.Handle(ctx, query)
	}
	b.log().Debug("blocked", "name", q.Name, "type", q.Type)
	return b.blockedReply(query), nil
}

// blockedReply builds the answer to a query for a blocked name.
func (b *Blocker) blockedReply(query *dnsmessage.Message) *dnsmessage.Message {
	if b.cfg.Mode == ModeNXDOMAIN {
		resp := dnsmessage.NewResponse(query, dnsmessage.RCodeNameError)
		resp.Header.Flags |= flagRA
		return resp
	}

	resp := dnsmessage.NewResponse(query, dnsmessage.RCodeSuccess)
	resp.Header.Flags |= flagRA
	q := query.Questions[0]
	var data dnsmessage.ResourceData
	switch q.Type {
	case dnsmessage.TypeA:
		data = dnsmessage.A{Addr: netip.IPv4Unspecified()}
	case dnsmessage.TypeAAAA:
		data = dnsmessage.AAAA{Addr: netip.IPv6Unspecified()}
	default:
		return resp // no records: the name exists, but has no data of this type
	}
	resp.Answers = []dnsmessage.ResourceRecord{{
		Name:  q.Name,
		Class: dnsmessage.ClassIN,
		TTL:   b.cfg.ttl(),
		Data:  data,
	}}
	return resp
}
