package blocklist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const flagRD = 0x0100

var upstreamAddr = netip.MustParseAddr("192.0.2.1")

// fakeNext stands in for the cache or forwarder. It answers every query with
// one A record and counts its calls.
type fakeNext struct{ calls atomic.Int32 }

func (f *fakeNext) Handle(_ context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
	f.calls.Add(1)
	r := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
	if len(q.Questions) == 1 {
		r.Answers = []dnsmessage.ResourceRecord{{
			Name: q.Questions[0].Name, Class: dnsmessage.ClassIN, TTL: 300, Data: dnsmessage.A{Addr: upstreamAddr},
		}}
	}
	return r, nil
}

func query(id uint16, name string, t dnsmessage.Type) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Flags: flagRD},
		Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassIN}},
	}
}

func newBlocker(t *testing.T, list string, cfg Config) (*Blocker, *fakeNext) {
	t.Helper()
	next := &fakeNext{}
	b, err := New(next, mustParse(t, list), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b, next
}

func ask(t *testing.T, b *Blocker, q *dnsmessage.Message) *dnsmessage.Message {
	t.Helper()
	reply, err := b.Handle(context.Background(), q)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return reply
}

func TestNew(t *testing.T) {
	list := mustParse(t, "")
	if _, err := New(nil, list, Config{}); !errors.Is(err, ErrNilHandler) {
		t.Errorf("nil handler: err = %v, want ErrNilHandler", err)
	}
	if _, err := New(&fakeNext{}, nil, Config{}); !errors.Is(err, ErrNilList) {
		t.Errorf("nil list: err = %v, want ErrNilList", err)
	}
}

func TestParseMode(t *testing.T) {
	for s, want := range map[string]Mode{"null": ModeNull, "nxdomain": ModeNXDOMAIN} {
		if got, err := ParseMode(s); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := ParseMode("NULL"); !errors.Is(err, ErrBadMode) {
		t.Errorf("ParseMode(NULL): err = %v, want ErrBadMode", err)
	}
}

func TestBlockedNullMode(t *testing.T) {
	tests := []struct {
		qtype    dnsmessage.Type
		wantData dnsmessage.ResourceData // nil means no records
	}{
		{dnsmessage.TypeA, dnsmessage.A{Addr: netip.MustParseAddr("0.0.0.0")}},
		{dnsmessage.TypeAAAA, dnsmessage.AAAA{Addr: netip.MustParseAddr("::")}},
		{dnsmessage.TypeMX, nil},
		{dnsmessage.TypeTXT, nil},
	}
	for _, tt := range tests {
		t.Run(tt.qtype.String(), func(t *testing.T) {
			b, next := newBlocker(t, "ads.example.com", Config{})
			reply := ask(t, b, query(42, "Ads.Example.com", tt.qtype))

			h := reply.Header
			if h.ID != 42 || !h.IsResponse() || !h.RecursionDesired() || !h.RecursionAvailable() || h.RCode() != dnsmessage.RCodeSuccess {
				t.Errorf("header = %+v, want ID 42, QR, RD, RA, NOERROR", h)
			}
			if got := reply.Questions[0].Name; got != "Ads.Example.com" {
				t.Errorf("question name = %q, want the query's own", got)
			}
			if tt.wantData == nil {
				if len(reply.Answers) != 0 {
					t.Errorf("answers = %+v, want none", reply.Answers)
				}
			} else {
				want := dnsmessage.ResourceRecord{Name: "Ads.Example.com", Class: dnsmessage.ClassIN, TTL: defaultTTL, Data: tt.wantData}
				if len(reply.Answers) != 1 || reply.Answers[0] != want {
					t.Errorf("answers = %+v, want %+v", reply.Answers, want)
				}
			}
			if n := next.calls.Load(); n != 0 {
				t.Errorf("next called %d times for a blocked name, want 0", n)
			}
		})
	}
}

func TestBlockedNXDOMAINMode(t *testing.T) {
	b, _ := newBlocker(t, "example.com", Config{Mode: ModeNXDOMAIN})
	reply := ask(t, b, query(1, "ads.example.com", dnsmessage.TypeA))
	if reply.Header.RCode() != dnsmessage.RCodeNameError || len(reply.Answers) != 0 {
		t.Errorf("reply = %+v, want NXDOMAIN with no records", reply)
	}
}

func TestBlockedTTL(t *testing.T) {
	b, _ := newBlocker(t, "example.com", Config{TTL: 120})
	if got := ask(t, b, query(1, "example.com", dnsmessage.TypeA)).Answers[0].TTL; got != 120 {
		t.Errorf("TTL = %d, want 120", got)
	}
}

func TestAllowedPassesThrough(t *testing.T) {
	b, next := newBlocker(t, "ads.example.com", Config{})
	reply := ask(t, b, query(1, "example.com", dnsmessage.TypeA))
	if n := next.calls.Load(); n != 1 {
		t.Errorf("next called %d times, want 1", n)
	}
	if len(reply.Answers) != 1 || reply.Answers[0].Data != (dnsmessage.A{Addr: upstreamAddr}) {
		t.Errorf("answers = %+v, want the upstream's", reply.Answers)
	}
}

func TestNotCheckedPassesThrough(t *testing.T) {
	chaos := query(1, "example.com", dnsmessage.TypeA)
	chaos.Questions[0].Class = 3
	two := query(2, "example.com", dnsmessage.TypeA)
	two.Questions = append(two.Questions, two.Questions[0])

	for name, q := range map[string]*dnsmessage.Message{"class CH": chaos, "two questions": two} {
		t.Run(name, func(t *testing.T) {
			b, next := newBlocker(t, "example.com", Config{})
			ask(t, b, q)
			if n := next.calls.Load(); n != 1 {
				t.Errorf("next called %d times, want 1", n)
			}
		})
	}
}

func TestSetList(t *testing.T) {
	b, _ := newBlocker(t, "old.example", Config{})

	if err := b.SetList(mustParse(t, "new.example")); err != nil {
		t.Fatal(err)
	}
	if got := ask(t, b, query(1, "old.example", dnsmessage.TypeA)).Answers[0].Data; got != (dnsmessage.A{Addr: upstreamAddr}) {
		t.Errorf("old.example still blocked after SetList")
	}
	if got := ask(t, b, query(2, "new.example", dnsmessage.TypeA)).Answers[0].Data; got != (dnsmessage.A{Addr: netip.IPv4Unspecified()}) {
		t.Errorf("new.example not blocked after SetList")
	}
	if err := b.SetList(nil); !errors.Is(err, ErrNilList) {
		t.Errorf("SetList(nil): err = %v, want ErrNilList", err)
	}
	if b.List().Len() != 1 {
		t.Error("SetList(nil) replaced the list")
	}
}

func TestConcurrentWithSetList(t *testing.T) {
	b, _ := newBlocker(t, "ads.example", Config{})
	lists := []*List{mustParse(t, "ads.example"), mustParse(t, "ads.example\nmore.example")}

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := uint16(i)
			reply, err := b.Handle(context.Background(), query(id, fmt.Sprintf("x%d.ads.example", i), dnsmessage.TypeA))
			if err != nil || reply.Header.ID != id || reply.Answers[0].Data != (dnsmessage.A{Addr: netip.IPv4Unspecified()}) {
				t.Errorf("query %d: reply %+v, err %v", i, reply, err)
			}
		})
		wg.Go(func() { b.SetList(lists[i%2]) })
	}
	wg.Wait()
}
