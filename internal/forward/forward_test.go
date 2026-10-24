package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	flagTC = 0x0200
	flagRD = 0x0100
	flagRA = 0x0080
)

var exampleA = dnsmessage.Question{Name: "example.com", Type: dnsmessage.TypeA, Class: dnsmessage.ClassIN}

var answerAddr = netip.MustParseAddr("192.0.2.1")

func clientQuery(id uint16, qs ...dnsmessage.Question) *dnsmessage.Message {
	return &dnsmessage.Message{Header: dnsmessage.Header{ID: id, Flags: flagRD}, Questions: qs}
}

func mustPack(m *dnsmessage.Message) []byte {
	b, err := m.Pack()
	if err != nil {
		panic(err) // a bug in the test itself
	}
	return b
}

// answer builds the reply a resolver would send to q: NOERROR, RA set, and
// one A record.
func answer(q *dnsmessage.Message) *dnsmessage.Message {
	r := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
	r.Header.Flags |= flagRA
	r.Answers = []dnsmessage.ResourceRecord{{
		Name:  q.Questions[0].Name,
		Class: dnsmessage.ClassIN,
		TTL:   300,
		Data:  dnsmessage.A{Addr: answerAddr},
	}}
	return r
}

// Reply functions for fakeUpstream.
func answering(q *dnsmessage.Message) [][]byte { return [][]byte{mustPack(answer(q))} }
func silent(*dnsmessage.Message) [][]byte      { return nil }

// upstream is a fake resolver listening on a loopback UDP port.
type upstream struct {
	addr string

	mu      sync.Mutex
	queries []*dnsmessage.Message
}

// received returns the queries the upstream has received so far.
func (u *upstream) received() []*dnsmessage.Message {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*dnsmessage.Message(nil), u.queries...)
}

// fakeUpstream starts a fake resolver. For each query it receives, it sends
// back the datagrams that reply returns, in order. It stops when the test ends.
func fakeUpstream(t *testing.T, reply func(q *dnsmessage.Message) [][]byte) *upstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{addr: pc.LocalAddr().String()}

	done := make(chan struct{})
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	go func() {
		defer close(done)
		buf := make([]byte, maxDatagramSize)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return // closed by the cleanup
			}
			q, err := dnsmessage.Unpack(buf[:n])
			if err != nil {
				continue
			}
			u.mu.Lock()
			u.queries = append(u.queries, q)
			u.mu.Unlock()
			for _, d := range reply(q) {
				pc.WriteTo(d, from)
			}
		}
	}()
	return u
}

// closedAddr returns a loopback address with nothing listening on it.
func closedAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func newForwarder(t *testing.T, timeout time.Duration, upstreams ...string) *Forwarder {
	t.Helper()
	f, err := New(Config{Upstreams: upstreams, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		upstreams []string
		wantErr   error
	}{
		{"one", []string{"1.1.1.1:53"}, nil},
		{"several", []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53", "dns.google:53"}, nil},
		{"nil", nil, ErrNoUpstreams},
		{"empty", []string{}, ErrNoUpstreams},
		{"no port", []string{"1.1.1.1"}, ErrBadUpstream},
		{"empty port", []string{"1.1.1.1:"}, ErrBadUpstream},
		{"no host", []string{":53"}, ErrBadUpstream},
		{"one bad among good", []string{"1.1.1.1:53", "nope"}, ErrBadUpstream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{Upstreams: tt.upstreams})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewCopiesUpstreams(t *testing.T) {
	upstreams := []string{"1.1.1.1:53"}
	f := newForwarder(t, 0, upstreams...)
	upstreams[0] = "changed:53"
	if got := f.cfg.Upstreams[0]; got != "1.1.1.1:53" {
		t.Errorf("upstream = %q after the caller changed its slice", got)
	}
}

func TestHandleAnswers(t *testing.T) {
	up := fakeUpstream(t, answering)
	f := newForwarder(t, time.Second, up.addr)
	f.newID = func() uint16 { return 0xbeef }

	reply, err := f.Handle(context.Background(), clientQuery(0x1234, exampleA))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	h := reply.Header
	if h.ID != 0x1234 || !h.IsResponse() || !h.RecursionAvailable() || h.RCode() != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v, want ID 0x1234, QR, RA, NOERROR", h)
	}
	want := []dnsmessage.ResourceRecord{{Name: "example.com", Class: dnsmessage.ClassIN, TTL: 300, Data: dnsmessage.A{Addr: answerAddr}}}
	if !reflect.DeepEqual(reply.Answers, want) {
		t.Errorf("answers = %+v, want %+v", reply.Answers, want)
	}

	seen := up.received()
	if len(seen) != 1 {
		t.Fatalf("upstream received %d queries, want 1", len(seen))
	}
	if seen[0].Header.ID != 0xbeef {
		t.Errorf("upstream saw ID 0x%04x, want the forwarder's own 0xbeef", seen[0].Header.ID)
	}
	if !seen[0].Header.RecursionDesired() {
		t.Error("RD flag was not passed on to the upstream")
	}
}

func TestHandleIgnoresStrayDatagrams(t *testing.T) {
	tests := []struct {
		name  string
		stray func(q *dnsmessage.Message) []byte
	}{
		{"wrong ID", func(q *dnsmessage.Message) []byte {
			r := answer(q)
			r.Header.ID ^= 1
			return mustPack(r)
		}},
		{"not a response", func(q *dnsmessage.Message) []byte { return mustPack(q) }},
		{"wrong name", func(q *dnsmessage.Message) []byte {
			r := answer(q)
			r.Questions[0].Name = "evil.example"
			return mustPack(r)
		}},
		{"wrong type", func(q *dnsmessage.Message) []byte {
			r := answer(q)
			r.Questions[0].Type = dnsmessage.TypeAAAA
			return mustPack(r)
		}},
		{"no question", func(q *dnsmessage.Message) []byte {
			r := answer(q)
			r.Questions = nil
			return mustPack(r)
		}},
		{"junk", func(*dnsmessage.Message) []byte { return []byte{1, 2, 3} }},
		{"right ID but does not parse", func(q *dnsmessage.Message) []byte {
			// A response header claiming one question that is not there.
			b := binary.BigEndian.AppendUint16(nil, q.Header.ID)
			return append(b, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := fakeUpstream(t, func(q *dnsmessage.Message) [][]byte {
				return [][]byte{tt.stray(q), mustPack(answer(q))}
			})
			f := newForwarder(t, time.Second, up.addr)

			reply, err := f.Handle(context.Background(), clientQuery(7, exampleA))
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if reply.Header.ID != 7 || len(reply.Answers) != 1 || reply.Questions[0] != exampleA {
				t.Errorf("got %+v, want the real answer", reply)
			}
		})
	}
}

func TestHandleNameCaseInsensitive(t *testing.T) {
	up := fakeUpstream(t, func(q *dnsmessage.Message) [][]byte {
		r := answer(q)
		r.Questions[0].Name = "ExAmPlE.CoM"
		return [][]byte{mustPack(r)}
	})
	f := newForwarder(t, time.Second, up.addr)

	if _, err := f.Handle(context.Background(), clientQuery(1, exampleA)); err != nil {
		t.Fatalf("reply with the name in other letter case was rejected: %v", err)
	}
}

// soaFixed holds an SOA's five 32-bit fields: serial 1, refresh 2, retry 3,
// expire 4 and minimum 5.
const soaFixed = "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"

// nxdomainWithSOA returns an NXDOMAIN reply for example.com A whose SOA names
// are compressed, pointing back into the question, as real resolvers send it.
func nxdomainWithSOA(id uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	return append(b, ""+
		"\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00"+ // QR RD RA NXDOMAIN, 1 question, 1 authority
		"\x07example\x03com\x00\x00\x01\x00\x01"+ // question at offset 12
		"\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x20"+ // example.com SOA IN, TTL 3600, RDLENGTH 32
		"\x02ns\xc0\x0c\x04host\xc0\x0c"+soaFixed...)
}

func TestHandleNXDOMAINWithCompressedSOA(t *testing.T) {
	up := fakeUpstream(t, func(q *dnsmessage.Message) [][]byte {
		return [][]byte{nxdomainWithSOA(q.Header.ID)}
	})
	f := newForwarder(t, time.Second, up.addr)

	reply, err := f.Handle(context.Background(), clientQuery(9, exampleA))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if reply.Header.RCode() != dnsmessage.RCodeNameError {
		t.Errorf("rcode = %v, want NXDOMAIN", reply.Header.RCode())
	}
	want := dnsmessage.SOA{MName: "ns.example.com", RName: "host.example.com", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5}
	if len(reply.Authorities) != 1 || reply.Authorities[0].Data != want {
		t.Fatalf("authorities = %+v, want one SOA %+v", reply.Authorities, want)
	}

	// What the server will do next: pack it for the client.
	again, err := dnsmessage.Unpack(mustPack(reply))
	if err != nil {
		t.Fatalf("re-packed reply does not parse: %v", err)
	}
	if !reflect.DeepEqual(again.Authorities, reply.Authorities) {
		t.Errorf("SOA changed when re-packed: %+v", again.Authorities)
	}
}

func TestHandlePassesTruncatedReplyOn(t *testing.T) {
	up := fakeUpstream(t, func(q *dnsmessage.Message) [][]byte {
		r := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
		r.Header.Flags |= flagTC
		return [][]byte{mustPack(r)}
	})
	f := newForwarder(t, time.Second, up.addr)

	reply, err := f.Handle(context.Background(), clientQuery(1, exampleA))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !reply.Header.Truncated() {
		t.Error("TC flag was lost")
	}
}

func TestHandleFallsBackToNextUpstream(t *testing.T) {
	const timeout = 100 * time.Millisecond

	t.Run("silent", func(t *testing.T) {
		dead, good := fakeUpstream(t, silent), fakeUpstream(t, answering)
		f := newForwarder(t, timeout, dead.addr, good.addr)

		start := time.Now()
		reply, err := f.Handle(context.Background(), clientQuery(1, exampleA))
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if len(reply.Answers) != 1 {
			t.Errorf("answers = %+v, want 1", reply.Answers)
		}
		if elapsed < timeout || elapsed > 10*timeout {
			t.Errorf("took %v, want about one timeout (%v)", elapsed, timeout)
		}
		if len(dead.received()) != 1 || len(good.received()) != 1 {
			t.Errorf("queries received: first %d, second %d, want 1 each", len(dead.received()), len(good.received()))
		}
	})

	t.Run("port closed", func(t *testing.T) {
		// The kernel reports "connection refused" on a connected socket, so
		// there is no need to wait for the timeout.
		good := fakeUpstream(t, answering)
		f := newForwarder(t, 5*time.Second, closedAddr(t), good.addr)

		start := time.Now()
		if _, err := f.Handle(context.Background(), clientQuery(1, exampleA)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("took %v, want the refusal to be noticed at once", elapsed)
		}
	})
}

func TestHandleNoAnswer(t *testing.T) {
	f := newForwarder(t, 50*time.Millisecond, fakeUpstream(t, silent).addr, fakeUpstream(t, silent).addr)

	_, err := f.Handle(context.Background(), clientQuery(1, exampleA))
	if !errors.Is(err, ErrNoAnswer) {
		t.Errorf("err = %v, want ErrNoAnswer", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("err = %v, want it to wrap os.ErrDeadlineExceeded", err)
	}
}

func TestHandleContext(t *testing.T) {
	t.Run("cancelled while waiting", func(t *testing.T) {
		up := fakeUpstream(t, silent)
		f := newForwarder(t, 10*time.Second, up.addr, up.addr)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(50*time.Millisecond, cancel)

		start := time.Now()
		_, err := f.Handle(ctx, clientQuery(1, exampleA))
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrNoAnswer) {
			t.Errorf("err = %v, want ErrNoAnswer wrapping context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("took %v to notice the cancellation", elapsed)
		}
		if n := len(up.received()); n != 1 {
			t.Errorf("upstream received %d queries, want 1: none after cancelling", n)
		}
	})

	t.Run("deadline shorter than timeout", func(t *testing.T) {
		f := newForwarder(t, 10*time.Second, fakeUpstream(t, silent).addr)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		if _, err := f.Handle(ctx, clientQuery(1, exampleA)); !errors.Is(err, ErrNoAnswer) {
			t.Errorf("err = %v, want ErrNoAnswer", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("took %v, want the context's deadline to apply", elapsed)
		}
	})
}

func TestHandleQuestionCount(t *testing.T) {
	up := fakeUpstream(t, answering)
	f := newForwarder(t, time.Second, up.addr)

	for _, qs := range [][]dnsmessage.Question{nil, {exampleA, exampleA}} {
		reply, err := f.Handle(context.Background(), clientQuery(3, qs...))
		if err != nil {
			t.Fatalf("%d questions: %v", len(qs), err)
		}
		if reply.Header.RCode() != dnsmessage.RCodeFormatError || reply.Header.ID != 3 {
			t.Errorf("%d questions: header = %+v, want FORMERR with ID 3", len(qs), reply.Header)
		}
	}
	if n := len(up.received()); n != 0 {
		t.Errorf("upstream received %d queries, want none", n)
	}
}

func TestHandleDropsClientRecords(t *testing.T) {
	up := fakeUpstream(t, answering)
	f := newForwarder(t, time.Second, up.addr)

	query := clientQuery(5, exampleA)
	query.Additionals = []dnsmessage.ResourceRecord{{
		Class: 1232, // an OPT record keeps the client's UDP size in the class field
		Data:  dnsmessage.Unknown{RRType: dnsmessage.TypeOPT, Data: []byte{}},
	}}

	if _, err := f.Handle(context.Background(), query); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	seen := up.received()
	if len(seen) != 1 || len(seen[0].Additionals) != 0 {
		t.Errorf("upstream query = %+v, want no additional records", seen)
	}
	if query.Header.ID != 5 || len(query.Additionals) != 1 {
		t.Errorf("the client's query was modified: %+v", query)
	}
}

func TestHandleConcurrent(t *testing.T) {
	up := fakeUpstream(t, answering)
	f := newForwarder(t, 2*time.Second, up.addr)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := uint16(i + 1)
			q := dnsmessage.Question{Name: fmt.Sprintf("host%d.example.com", i), Type: dnsmessage.TypeA, Class: dnsmessage.ClassIN}
			reply, err := f.Handle(context.Background(), clientQuery(id, q))
			if err != nil {
				t.Errorf("query %d: %v", i, err)
				return
			}
			if reply.Header.ID != id || reply.Questions[0] != q {
				t.Errorf("query %d got the reply for ID %d, %s", i, reply.Header.ID, reply.Questions[0].Name)
			}
		})
	}
	wg.Wait()
}
