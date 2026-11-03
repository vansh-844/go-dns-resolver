package cache

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const flagTC = 0x0200

var answerAddr = netip.MustParseAddr("192.0.2.1")

func question(name string, t dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: name, Type: t, Class: dnsmessage.ClassIN}
}

func query(id uint16, qs ...dnsmessage.Question) *dnsmessage.Message {
	return &dnsmessage.Message{Header: dnsmessage.Header{ID: id, Flags: flagRD}, Questions: qs}
}

// withA is a reply: NOERROR with one A record of the given TTL.
func withA(ttl uint32) func(q *dnsmessage.Message) *dnsmessage.Message {
	return func(q *dnsmessage.Message) *dnsmessage.Message {
		r := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
		r.Answers = []dnsmessage.ResourceRecord{{
			Name: q.Questions[0].Name, Class: dnsmessage.ClassIN, TTL: ttl, Data: dnsmessage.A{Addr: answerAddr},
		}}
		return r
	}
}

// negative is a reply with rcode and, if soaTTL is not zero, an SOA in the
// authority section with that TTL and the given minimum.
func negative(rcode dnsmessage.RCode, soaTTL, minimum uint32) func(q *dnsmessage.Message) *dnsmessage.Message {
	return func(q *dnsmessage.Message) *dnsmessage.Message {
		r := dnsmessage.NewResponse(q, rcode)
		if soaTTL != 0 {
			r.Authorities = []dnsmessage.ResourceRecord{{
				Name: "example.com", Class: dnsmessage.ClassIN, TTL: soaTTL,
				Data: dnsmessage.SOA{MName: "ns.example.com", RName: "host.example.com", Minimum: minimum},
			}}
		}
		return r
	}
}

// fakeNext is the handler behind the cache. It counts its calls and builds
// its reply with reply, or fails with err.
type fakeNext struct {
	reply func(q *dnsmessage.Message) *dnsmessage.Message
	err   error

	mu    sync.Mutex
	calls int
}

func (f *fakeNext) Handle(_ context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.reply(q), nil
}

func (f *fakeNext) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeClock is a time that moves only when told to.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newCache(t *testing.T, next Handler, cfg Config) (*Cache, *fakeClock) {
	t.Helper()
	c, err := New(next, cfg)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c.now = clock.now
	return c, clock
}

func ask(t *testing.T, c *Cache, q *dnsmessage.Message) *dnsmessage.Message {
	t.Helper()
	reply, err := c.Handle(context.Background(), q)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return reply
}

func TestNewNilHandler(t *testing.T) {
	if _, err := New(nil, Config{}); !errors.Is(err, ErrNilHandler) {
		t.Errorf("err = %v, want ErrNilHandler", err)
	}
}

func TestHit(t *testing.T) {
	next := &fakeNext{reply: withA(300)}
	c, _ := newCache(t, next, Config{})
	q := question("example.com", dnsmessage.TypeA)

	first := ask(t, c, query(1, q))
	second := ask(t, c, query(2, q))

	if n := next.count(); n != 1 {
		t.Errorf("next called %d times, want 1", n)
	}
	if first.Header.ID != 1 || second.Header.ID != 2 {
		t.Errorf("IDs = %d, %d, want 1, 2", first.Header.ID, second.Header.ID)
	}
	if len(second.Answers) != 1 || second.Answers[0].Data != (dnsmessage.A{Addr: answerAddr}) {
		t.Errorf("cached answers = %+v", second.Answers)
	}
}

func TestTTLCountsDown(t *testing.T) {
	c, clock := newCache(t, &fakeNext{reply: withA(300)}, Config{})
	q := question("example.com", dnsmessage.TypeA)

	ask(t, c, query(1, q))
	clock.advance(10 * time.Second)
	if got := ask(t, c, query(2, q)).Answers[0].TTL; got != 290 {
		t.Errorf("TTL after 10s = %d, want 290", got)
	}
	// 289.5s are left, rounded down: a client is never told it may keep an
	// answer longer than the cache does.
	clock.advance(500 * time.Millisecond)
	if got := ask(t, c, query(3, q)).Answers[0].TTL; got != 289 {
		t.Errorf("TTL after 10.5s = %d, want 289", got)
	}
}

func TestExpiry(t *testing.T) {
	next := &fakeNext{reply: withA(60)}
	c, clock := newCache(t, next, Config{})
	q := question("example.com", dnsmessage.TypeA)

	ask(t, c, query(1, q))
	clock.advance(59 * time.Second)
	ask(t, c, query(2, q))
	if n := next.count(); n != 1 {
		t.Fatalf("next called %d times before expiry, want 1", n)
	}

	clock.advance(time.Second)
	ask(t, c, query(3, q))
	if n := next.count(); n != 2 {
		t.Errorf("next called %d times after expiry, want 2", n)
	}
}

func TestCaseInsensitive(t *testing.T) {
	next := &fakeNext{reply: withA(300)}
	c, _ := newCache(t, next, Config{})

	ask(t, c, query(1, question("example.com", dnsmessage.TypeA)))
	reply := ask(t, c, query(2, question("EXAMPLE.com", dnsmessage.TypeA)))

	if n := next.count(); n != 1 {
		t.Errorf("next called %d times, want 1", n)
	}
	if got := reply.Questions[0].Name; got != "EXAMPLE.com" {
		t.Errorf("question name = %q, want the query's own EXAMPLE.com", got)
	}
}

func TestDifferentTypeMisses(t *testing.T) {
	next := &fakeNext{reply: withA(300)}
	c, _ := newCache(t, next, Config{})

	ask(t, c, query(1, question("example.com", dnsmessage.TypeA)))
	ask(t, c, query(2, question("example.com", dnsmessage.TypeAAAA)))
	if n := next.count(); n != 2 {
		t.Errorf("next called %d times, want 2", n)
	}
}

func TestRDEchoed(t *testing.T) {
	c, _ := newCache(t, &fakeNext{reply: withA(300)}, Config{})
	q := question("example.com", dnsmessage.TypeA)

	ask(t, c, query(1, q)) // stored from a query with RD set
	noRD := query(2, q)
	noRD.Header.Flags = 0
	if ask(t, c, noRD).Header.RecursionDesired() {
		t.Error("cached reply has RD set for a query without it")
	}
}

func TestNegative(t *testing.T) {
	tests := []struct {
		name       string
		reply      func(q *dnsmessage.Message) *dnsmessage.Message
		wantCached time.Duration // 0 means not cached
	}{
		{"NXDOMAIN uses SOA minimum", negative(dnsmessage.RCodeNameError, 3600, 60), 60 * time.Second},
		{"NXDOMAIN uses SOA TTL when lower", negative(dnsmessage.RCodeNameError, 30, 900), 30 * time.Second},
		{"no data", negative(dnsmessage.RCodeSuccess, 3600, 60), 60 * time.Second},
		{"NXDOMAIN without SOA", negative(dnsmessage.RCodeNameError, 0, 0), 0},
		{"no data without SOA", negative(dnsmessage.RCodeSuccess, 0, 0), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &fakeNext{reply: tt.reply}
			c, clock := newCache(t, next, Config{})
			q := question("nope.example.com", dnsmessage.TypeA)

			ask(t, c, query(1, q))
			if tt.wantCached == 0 {
				ask(t, c, query(2, q))
				if n := next.count(); n != 2 {
					t.Errorf("next called %d times, want 2 (not cached)", n)
				}
				return
			}

			clock.advance(tt.wantCached - time.Second)
			reply := ask(t, c, query(2, q))
			if n := next.count(); n != 1 {
				t.Fatalf("next called %d times just before expiry, want 1", n)
			}
			if reply.Header.RCode() != tt.reply(query(0, q)).Header.RCode() {
				t.Errorf("cached rcode = %v", reply.Header.RCode())
			}
			if got := reply.Authorities[0].TTL; got != 1 {
				t.Errorf("SOA TTL with 1s left = %d, want 1", got)
			}

			clock.advance(time.Second)
			ask(t, c, query(3, q))
			if n := next.count(); n != 2 {
				t.Errorf("next called %d times after expiry, want 2", n)
			}
		})
	}
}

func TestNotCached(t *testing.T) {
	truncated := func(q *dnsmessage.Message) *dnsmessage.Message {
		r := withA(300)(q)
		r.Header.Flags |= flagTC
		return r
	}
	tests := []struct {
		name  string
		reply func(q *dnsmessage.Message) *dnsmessage.Message
	}{
		{"SERVFAIL", negative(dnsmessage.RCodeServerFailure, 3600, 60)},
		{"REFUSED", negative(dnsmessage.RCodeRefused, 3600, 60)},
		{"truncated", truncated},
		{"TTL 0", withA(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &fakeNext{reply: tt.reply}
			c, _ := newCache(t, next, Config{})
			q := question("example.com", dnsmessage.TypeA)

			ask(t, c, query(1, q))
			ask(t, c, query(2, q))
			if n := next.count(); n != 2 {
				t.Errorf("next called %d times, want 2", n)
			}
			if n := c.Len(); n != 0 {
				t.Errorf("cache holds %d entries, want 0", n)
			}
		})
	}

	t.Run("error", func(t *testing.T) {
		boom := errors.New("upstream down")
		next := &fakeNext{err: boom}
		c, _ := newCache(t, next, Config{})
		q := query(1, question("example.com", dnsmessage.TypeA))

		for range 2 {
			if _, err := c.Handle(context.Background(), q); !errors.Is(err, boom) {
				t.Errorf("err = %v, want the handler's error", err)
			}
		}
		if n := next.count(); n != 2 {
			t.Errorf("next called %d times, want 2", n)
		}
	})
}

func TestMaxTTL(t *testing.T) {
	next := &fakeNext{reply: withA(7 * 24 * 3600)}
	c, clock := newCache(t, next, Config{MaxTTL: time.Hour})
	q := question("example.com", dnsmessage.TypeA)

	ask(t, c, query(1, q))
	clock.advance(time.Minute)
	if got := ask(t, c, query(2, q)).Answers[0].TTL; got != 59*60 {
		t.Errorf("TTL = %d, want %d: no more than the entry has left", got, 59*60)
	}

	clock.advance(time.Hour)
	ask(t, c, query(3, q))
	if n := next.count(); n != 2 {
		t.Errorf("next called %d times, want 2: MaxTTL should have expired the entry", n)
	}
}

func TestLRUEviction(t *testing.T) {
	next := &fakeNext{reply: withA(300)}
	c, _ := newCache(t, next, Config{MaxEntries: 2})
	a := question("a.example", dnsmessage.TypeA)
	b := question("b.example", dnsmessage.TypeA)
	d := question("d.example", dnsmessage.TypeA)

	ask(t, c, query(1, a))
	ask(t, c, query(2, b))
	ask(t, c, query(3, a)) // a is now the most recently used
	ask(t, c, query(4, d)) // full: b, the least recently used, goes
	if n := c.Len(); n != 2 {
		t.Errorf("cache holds %d entries, want 2", n)
	}

	calls := next.count()
	ask(t, c, query(5, a))
	if next.count() != calls {
		t.Error("a was evicted, want it kept as recently used")
	}
	ask(t, c, query(6, b))
	if next.count() != calls+1 {
		t.Error("b was still cached, want it evicted")
	}
}

func TestRepliesDoNotAlias(t *testing.T) {
	c, _ := newCache(t, &fakeNext{reply: withA(300)}, Config{})
	q := question("example.com", dnsmessage.TypeA)

	first := ask(t, c, query(1, q)) // the reply that was stored
	first.Answers[0].TTL = 1
	second := ask(t, c, query(2, q))
	second.Answers[0].TTL = 2
	second.Questions[0].Name = "changed"

	third := ask(t, c, query(3, q))
	if third.Answers[0].TTL != 300 || third.Questions[0].Name != "example.com" {
		t.Errorf("cached entry changed through a returned reply: %+v", third)
	}
}

func TestPassThrough(t *testing.T) {
	notQuery := query(1, question("example.com", dnsmessage.TypeA))
	notQuery.Header.Flags |= 2 << 11 // opcode 2, STATUS

	tests := []struct {
		name  string
		query *dnsmessage.Message
	}{
		{"two questions", query(1, question("a.example", dnsmessage.TypeA), question("b.example", dnsmessage.TypeA))},
		{"not a standard query", notQuery},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &fakeNext{reply: withA(300)}
			c, _ := newCache(t, next, Config{})
			ask(t, c, tt.query)
			ask(t, c, tt.query)
			if n := next.count(); n != 2 {
				t.Errorf("next called %d times, want 2", n)
			}
		})
	}
}

func TestConcurrent(t *testing.T) {
	next := &fakeNext{reply: withA(300)}
	c, clock := newCache(t, next, Config{MaxEntries: 3})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := uint16(i + 1)
			q := question(fmt.Sprintf("host%d.example", i%5), dnsmessage.TypeA)
			reply, err := c.Handle(context.Background(), query(id, q))
			if err != nil {
				t.Errorf("query %d: %v", i, err)
				return
			}
			if reply.Header.ID != id || reply.Questions[0] != q {
				t.Errorf("query %d got the reply for ID %d, %s", i, reply.Header.ID, reply.Questions[0].Name)
			}
			clock.advance(time.Second)
		})
	}
	wg.Wait()
	if n := c.Len(); n > 3 {
		t.Errorf("cache holds %d entries, want at most 3", n)
	}
}
