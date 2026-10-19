package server

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	flagRD = 0x0100
	flagAA = 0x0400
	flagRA = 0x0080
)

func newQuery(id uint16, flags uint16, qs ...dnsmessage.Question) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Flags: flags},
		Questions: qs,
	}
}

func question(name string, t dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: name, Type: t, Class: dnsmessage.ClassIN}
}

func TestNewStaticHandler(t *testing.T) {
	if _, err := NewStaticHandler(netip.MustParseAddr("1.2.3.4"), 60); err != nil {
		t.Errorf("IPv4: %v", err)
	}
	for _, addr := range []netip.Addr{netip.MustParseAddr("::1"), {}} {
		if _, err := NewStaticHandler(addr, 60); !errors.Is(err, ErrNotIPv4) {
			t.Errorf("addr %v: err = %v, want ErrNotIPv4", addr, err)
		}
	}
}

func TestStaticHandler(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.7")
	h, err := NewStaticHandler(ip, 120)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		query       *dnsmessage.Message
		wantRCode   dnsmessage.RCode
		wantAnswers []dnsmessage.ResourceRecord
		wantFlags   uint16 // flags expected apart from QR, the opcode and the RCode
		wantOpcode  uint8
	}{
		{
			name:      "A query",
			query:     newQuery(1, flagRD, question("example.com", dnsmessage.TypeA)),
			wantRCode: dnsmessage.RCodeSuccess,
			wantAnswers: []dnsmessage.ResourceRecord{{
				Name: "example.com", Class: dnsmessage.ClassIN, TTL: 120, Data: dnsmessage.A{Addr: ip},
			}},
			wantFlags: flagRD,
		},
		{
			name:      "recursion not desired is copied",
			query:     newQuery(2, 0, question("example.com", dnsmessage.TypeA)),
			wantRCode: dnsmessage.RCodeSuccess,
			wantAnswers: []dnsmessage.ResourceRecord{{
				Name: "example.com", Class: dnsmessage.ClassIN, TTL: 120, Data: dnsmessage.A{Addr: ip},
			}},
			wantFlags: 0,
		},
		{
			name:      "name case is preserved",
			query:     newQuery(3, flagRD, question("ExAmPlE.CoM", dnsmessage.TypeA)),
			wantRCode: dnsmessage.RCodeSuccess,
			wantAnswers: []dnsmessage.ResourceRecord{{
				Name: "ExAmPlE.CoM", Class: dnsmessage.ClassIN, TTL: 120, Data: dnsmessage.A{Addr: ip},
			}},
			wantFlags: flagRD,
		},
		{
			name:      "AAAA gets no answers",
			query:     newQuery(4, flagRD, question("example.com", dnsmessage.TypeAAAA)),
			wantRCode: dnsmessage.RCodeSuccess,
			wantFlags: flagRD,
		},
		{
			name:      "no questions",
			query:     newQuery(5, flagRD),
			wantRCode: dnsmessage.RCodeFormatError,
			wantFlags: flagRD,
		},
		{
			name: "two questions",
			query: newQuery(6, flagRD,
				question("a.example.com", dnsmessage.TypeA), question("b.example.com", dnsmessage.TypeA)),
			wantRCode: dnsmessage.RCodeFormatError,
			wantFlags: flagRD,
		},
		{
			name:       "unsupported opcode",
			query:      newQuery(7, 2<<11|flagRD, question("example.com", dnsmessage.TypeA)),
			wantRCode:  dnsmessage.RCodeNotImplemented,
			wantFlags:  flagRD,
			wantOpcode: 2,
		},
		{
			name: "class CHAOS",
			query: newQuery(8, flagRD,
				dnsmessage.Question{Name: "version.bind", Type: dnsmessage.TypeTXT, Class: 3}),
			wantRCode: dnsmessage.RCodeRefused,
			wantFlags: flagRD,
		},
		{
			name:      "unrelated flags are not copied",
			query:     newQuery(9, flagRD|flagAA|flagRA|0x0200, question("example.com", dnsmessage.TypeA)),
			wantRCode: dnsmessage.RCodeSuccess,
			wantAnswers: []dnsmessage.ResourceRecord{{
				Name: "example.com", Class: dnsmessage.ClassIN, TTL: 120, Data: dnsmessage.A{Addr: ip},
			}},
			wantFlags: flagRD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantQuestions := append([]dnsmessage.Question(nil), tt.query.Questions...)

			resp, err := h.Handle(context.Background(), tt.query)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Header.ID != tt.query.Header.ID {
				t.Errorf("ID = %d, want %d", resp.Header.ID, tt.query.Header.ID)
			}
			if !resp.Header.IsResponse() {
				t.Error("QR bit not set")
			}
			if got := resp.Header.RCode(); got != tt.wantRCode {
				t.Errorf("RCode = %v, want %v", got, tt.wantRCode)
			}
			if got := resp.Header.Opcode(); got != tt.wantOpcode {
				t.Errorf("Opcode = %d, want %d", got, tt.wantOpcode)
			}
			const other = 0x8000 | 0x7800 | 0xF // QR, opcode and RCode bits
			if got := resp.Header.Flags &^ other; got != tt.wantFlags {
				t.Errorf("other flags = %#04x, want %#04x", got, tt.wantFlags)
			}
			if !reflect.DeepEqual(resp.Questions, wantQuestions) {
				t.Errorf("questions = %+v, want %+v", resp.Questions, wantQuestions)
			}
			if !reflect.DeepEqual(resp.Answers, tt.wantAnswers) {
				t.Errorf("answers = %+v, want %+v", resp.Answers, tt.wantAnswers)
			}
			if len(resp.Authorities) != 0 || len(resp.Additionals) != 0 {
				t.Errorf("unexpected authority or additional records: %+v", resp)
			}

			// The response must also survive the wire.
			wire, err := resp.Pack()
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if _, err := dnsmessage.Unpack(wire); err != nil {
				t.Fatalf("Unpack: %v", err)
			}
		})
	}
}

func TestStaticHandlerDoesNotAliasQuery(t *testing.T) {
	h, err := NewStaticHandler(netip.MustParseAddr("192.0.2.7"), 1)
	if err != nil {
		t.Fatal(err)
	}
	query := newQuery(1, flagRD, question("example.com", dnsmessage.TypeA))
	resp, err := h.Handle(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	resp.Questions[0].Name = "changed.example"
	if query.Questions[0].Name != "example.com" {
		t.Errorf("changing the response changed the query: %+v", query.Questions[0])
	}
}
