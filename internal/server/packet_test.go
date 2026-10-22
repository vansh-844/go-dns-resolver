package server

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const flagTC = 0x0200

func queryBytes(t *testing.T, id uint16, flags uint16, qs ...dnsmessage.Question) []byte {
	t.Helper()
	wire, err := newQuery(id, flags, qs...).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustUnpack(t *testing.T, wire []byte) *dnsmessage.Message {
	t.Helper()
	m, err := dnsmessage.Unpack(wire)
	if err != nil {
		t.Fatalf("reply does not unpack: %v", err)
	}
	return m
}

func serverWith(t *testing.T, h Handler) *Server {
	t.Helper()
	s, err := NewServer(ServerConfig{Addr: "127.0.0.1", Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func staticServer(t *testing.T) *Server {
	t.Helper()
	h, err := NewStaticHandler(netip.MustParseAddr("192.0.2.7"), 60)
	if err != nil {
		t.Fatal(err)
	}
	return serverWith(t, h)
}

func TestHandlePacketAnswersQuery(t *testing.T) {
	s := staticServer(t)
	reply := s.handlePacket(context.Background(),
		queryBytes(t, 0x1234, flagRD, question("example.com", dnsmessage.TypeA)))

	m := mustUnpack(t, reply)
	if m.Header.ID != 0x1234 || !m.Header.IsResponse() || m.Header.RCode() != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v", m.Header)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %+v, want 1", m.Answers)
	}
	if a, ok := m.Answers[0].Data.(dnsmessage.A); !ok || a.Addr != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("answer = %+v", m.Answers[0])
	}
}

func TestHandlePacketDrops(t *testing.T) {
	s := staticServer(t)
	query := queryBytes(t, 1, flagRD, question("example.com", dnsmessage.TypeA))

	response := append([]byte(nil), query...)
	response[2] |= 0x80 // set QR on an otherwise valid packet

	// A header that claims a question but has none: it cannot be parsed, and
	// is marked as a response.
	unparseableResponse := []byte{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{1}},
		{"two bytes", []byte{1, 2}},
		{"one byte short of a header", query[:headerLen-1]},
		{"valid packet with QR set", response},
		{"unparseable packet with QR set", unparseableResponse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if reply := s.handlePacket(context.Background(), tt.data); reply != nil {
				t.Errorf("got reply % x, want none", reply)
			}
		})
	}
}

func TestHandlePacketFormErr(t *testing.T) {
	s := staticServer(t)
	// A header claiming one question, followed by nothing.
	data := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}

	reply := s.handlePacket(context.Background(), data)
	if reply == nil {
		t.Fatal("no reply to an unparseable packet")
	}
	if len(reply) > len(data) {
		t.Errorf("reply is %d bytes for a %d-byte packet", len(reply), len(data))
	}
	m := mustUnpack(t, reply)
	if m.Header.ID != 0xabcd || !m.Header.IsResponse() ||
		m.Header.RCode() != dnsmessage.RCodeFormatError || !m.Header.RecursionDesired() {
		t.Errorf("header = %+v", m.Header)
	}
	if len(m.Questions) != 0 || len(m.Answers) != 0 {
		t.Errorf("reply has records: %+v", m)
	}
}

func TestHandlePacketServFail(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		handler HandlerFunc
	}{
		{"handler error", func(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) {
			return nil, boom
		}},
		{"handler error with a response", func(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) {
			return &dnsmessage.Message{}, boom
		}},
		{"nil response and no error", func(context.Context, *dnsmessage.Message) (*dnsmessage.Message, error) {
			return nil, nil
		}},
		{"response that cannot be packed", func(_ context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
			resp := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
			resp.Answers = []dnsmessage.ResourceRecord{{Name: "example.com", Class: dnsmessage.ClassIN}} // no data
			return resp, nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := serverWith(t, tt.handler)
			q := question("example.com", dnsmessage.TypeA)
			m := mustUnpack(t, s.handlePacket(context.Background(), queryBytes(t, 77, flagRD, q)))

			if m.Header.ID != 77 || !m.Header.IsResponse() || m.Header.RCode() != dnsmessage.RCodeServerFailure {
				t.Errorf("header = %+v", m.Header)
			}
			if len(m.Questions) != 1 || m.Questions[0] != q {
				t.Errorf("questions = %+v, want the query's", m.Questions)
			}
			if len(m.Answers) != 0 {
				t.Errorf("answers = %+v, want none", m.Answers)
			}
		})
	}
}

func TestHandlePacketTruncatesOversizedResponse(t *testing.T) {
	big := HandlerFunc(func(_ context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
		resp := dnsmessage.NewResponse(q, dnsmessage.RCodeSuccess)
		for i := 0; i < 100; i++ {
			resp.Answers = append(resp.Answers, dnsmessage.ResourceRecord{
				Name: q.Questions[0].Name, Class: dnsmessage.ClassIN, TTL: 60,
				Data: dnsmessage.A{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})},
			})
		}
		return resp, nil
	})
	s := serverWith(t, big)
	q := question("example.com", dnsmessage.TypeA)

	reply := s.handlePacket(context.Background(), queryBytes(t, 5, flagRD, q))
	if len(reply) > maxUDPSize {
		t.Errorf("reply is %d bytes, want at most %d", len(reply), maxUDPSize)
	}
	m := mustUnpack(t, reply)
	if m.Header.Flags&flagTC == 0 {
		t.Error("TC flag not set")
	}
	if m.Header.ID != 5 || m.Header.RCode() != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v", m.Header)
	}
	if len(m.Questions) != 1 || m.Questions[0] != q {
		t.Errorf("questions = %+v", m.Questions)
	}
	if len(m.Answers) != 0 {
		t.Errorf("answers = %d, want none", len(m.Answers))
	}
}

func TestHandlePacketLeavesSmallResponseAlone(t *testing.T) {
	s := staticServer(t)
	reply := s.handlePacket(context.Background(),
		queryBytes(t, 1, flagRD, question("example.com", dnsmessage.TypeA)))
	if m := mustUnpack(t, reply); m.Header.Flags&flagTC != 0 {
		t.Error("TC flag set on a small response")
	}
}
