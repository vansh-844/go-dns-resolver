package dnsmessage

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustAppendQuestion(t *testing.T, b []byte, q Question) []byte {
	t.Helper()
	b, err := q.appendTo(b)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustAppendRecord(t *testing.T, b []byte, rr ResourceRecord) []byte {
	t.Helper()
	b, err := rr.appendTo(b)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnpack(t *testing.T) {
	t.Run("response from the briefing", func(t *testing.T) {
		got, err := Unpack(exampleResponse())
		if err != nil {
			t.Fatal(err)
		}
		want := &Message{
			Header:    Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1},
			Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
			Answers: []ResourceRecord{{
				Name: "example.com", Class: ClassIN, TTL: 300,
				Data: A{netip.MustParseAddr("93.184.216.34")},
			}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("all sections", func(t *testing.T) {
		q := Question{Name: "example.com", Type: TypeNS, Class: ClassIN}
		an := ResourceRecord{Name: "example.com", Class: ClassIN, TTL: 60, Data: NS{"ns1.example.com"}}
		ns1 := ResourceRecord{Name: "example.com", Class: ClassIN, TTL: 61, Data: NS{"ns2.example.com"}}
		ns2 := ResourceRecord{Name: "example.com", Class: ClassIN, TTL: 62, Data: MX{10, "mail.example.com"}}
		ar := ResourceRecord{Name: "ns1.example.com", Class: ClassIN, TTL: 63, Data: A{netip.MustParseAddr("192.0.2.1")}}

		h := Header{ID: 7, Flags: 0x8400, QDCount: 1, ANCount: 1, NSCount: 2, ARCount: 1}
		wire := h.appendTo(nil)
		wire = mustAppendQuestion(t, wire, q)
		for _, rr := range []ResourceRecord{an, ns1, ns2, ar} {
			wire = mustAppendRecord(t, wire, rr)
		}

		got, err := Unpack(wire)
		if err != nil {
			t.Fatal(err)
		}
		want := &Message{
			Header:      h,
			Questions:   []Question{q},
			Answers:     []ResourceRecord{an},
			Authorities: []ResourceRecord{ns1, ns2},
			Additionals: []ResourceRecord{ar},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("header only", func(t *testing.T) {
		got, err := Unpack(responseHeader[:0:0])
		if err == nil {
			t.Fatalf("got %+v, want error", got)
		}
		h := Header{ID: 1, Flags: 0x8000}
		got, err = Unpack(h.appendTo(nil))
		if err != nil {
			t.Fatal(err)
		}
		if want := (&Message{Header: h}); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("trailing bytes are ignored", func(t *testing.T) {
		wire := append(exampleResponse(), 0xde, 0xad, 0xbe, 0xef)
		got, err := Unpack(wire)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Questions) != 1 || len(got.Answers) != 1 {
			t.Errorf("got %+v", got)
		}
	})
}

func TestUnpackTruncatedAnywhere(t *testing.T) {
	wire := exampleResponse()
	for n := 0; n < len(wire); n++ {
		got, err := Unpack(wire[:n])
		if got != nil {
			t.Fatalf("len %d: got message %+v, want nil", n, got)
		}
		if !errors.Is(err, ErrShortBuffer) {
			t.Errorf("len %d: err = %v, want ErrShortBuffer", n, err)
		}
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("len %d: err %T is not a *ParseError", n, err)
		}
	}
}

func TestUnpackParseError(t *testing.T) {
	good := ResourceRecord{Name: "a", Class: ClassIN, Data: A{netip.MustParseAddr("1.2.3.4")}}
	// A record whose RDLENGTH is 3, which is wrong for type A.
	badA := []byte("\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03")

	tests := []struct {
		name        string
		build       func(t *testing.T) []byte
		wantSection string
		wantOffset  func(wire []byte) int
		wantErr     error
	}{
		{
			name: "short header",
			build: func(t *testing.T) []byte {
				return []byte{1, 2, 3}
			},
			wantSection: "header",
			wantOffset:  func([]byte) int { return 0 },
			wantErr:     ErrShortBuffer,
		},
		{
			name: "claims a question but has none",
			build: func(t *testing.T) []byte {
				return Header{QDCount: 1}.appendTo(nil)
			},
			wantSection: "question[0]",
			wantOffset:  func([]byte) int { return headerSize },
			wantErr:     ErrShortBuffer,
		},
		{
			name: "second answer is malformed",
			build: func(t *testing.T) []byte {
				wire := Header{ANCount: 2}.appendTo(nil)
				wire = mustAppendRecord(t, wire, good)
				return append(wire, badA...)
			},
			wantSection: "answer[1]",
			wantOffset: func(wire []byte) int {
				return len(wire) - len("\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03")
			},
			wantErr: ErrBadRDLength,
		},
		{
			name: "authority record missing",
			build: func(t *testing.T) []byte {
				return Header{NSCount: 1}.appendTo(nil)
			},
			wantSection: "authority[0]",
			wantOffset:  func([]byte) int { return headerSize },
			wantErr:     ErrShortBuffer,
		},
		{
			name: "additional record missing",
			build: func(t *testing.T) []byte {
				return Header{ARCount: 1}.appendTo(nil)
			},
			wantSection: "additional[0]",
			wantOffset:  func([]byte) int { return headerSize },
			wantErr:     ErrShortBuffer,
		},
		{
			name: "bad name in question",
			build: func(t *testing.T) []byte {
				return append(Header{QDCount: 1}.appendTo(nil), 0x40, 0, 0, 1, 0, 1)
			},
			wantSection: "question[0]",
			wantOffset:  func([]byte) int { return headerSize },
			wantErr:     ErrBadLabelType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.build(t)
			got, err := Unpack(wire)
			if got != nil {
				t.Errorf("got message %+v, want nil", got)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v (%T), want *ParseError", err, err)
			}
			if pe.Section != tt.wantSection || pe.Offset != tt.wantOffset(wire) {
				t.Errorf("section/offset = %q/%d, want %q/%d", pe.Section, pe.Offset, tt.wantSection, tt.wantOffset(wire))
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnpackLyingCounts(t *testing.T) {
	// Every count claims 65535 entries but no data follows. This must fail
	// quickly without allocating room for hundreds of thousands of entries.
	h := Header{QDCount: 0xffff, ANCount: 0xffff, NSCount: 0xffff, ARCount: 0xffff}
	wire := h.appendTo(nil)

	allocs := testing.AllocsPerRun(10, func() {
		if _, err := Unpack(wire); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("err = %v, want ErrShortBuffer", err)
		}
	})
	if allocs > 10 {
		t.Errorf("allocs = %v, want a small constant", allocs)
	}

	// Same with enough data for one question only: the first answer fails.
	h = Header{QDCount: 1, ANCount: 0xffff}
	wire = mustAppendQuestion(t, h.appendTo(nil), Question{Name: "a", Type: TypeA, Class: ClassIN})
	_, err := Unpack(wire)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Section != "answer[0]" {
		t.Errorf("err = %v, want ParseError in answer[0]", err)
	}
}

func TestPackRoundTrip(t *testing.T) {
	full := Message{
		Header:    Header{ID: 7, Flags: 0x8400},
		Questions: []Question{{Name: "example.com", Type: TypeNS, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "example.com", Class: ClassIN, TTL: 60, Data: NS{"ns1.example.com"}},
		},
		Authorities: []ResourceRecord{
			{Name: "example.com", Class: ClassIN, TTL: 61, Data: MX{10, "mail.example.com"}},
			{Name: "example.com", Class: ClassIN, TTL: 62, Data: TXT{[]string{"a", "b"}}},
		},
		Additionals: []ResourceRecord{
			{Name: "ns1.example.com", Class: ClassIN, TTL: 63, Data: AAAA{netip.MustParseAddr("2001:db8::1")}},
		},
	}
	full.Header.QDCount, full.Header.ANCount, full.Header.NSCount, full.Header.ARCount = 1, 1, 2, 1

	fromWire, err := Unpack(exampleResponse())
	if err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]*Message{
		"full":            &full,
		"empty":           {Header: Header{ID: 1}},
		"parsed response": fromWire,
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := want.Pack()
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unpack(wire)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestPackDerivesCounts(t *testing.T) {
	m := &Message{
		Header:    Header{ID: 9, Flags: 0x8180, QDCount: 5, ANCount: 0, NSCount: 3, ARCount: 7},
		Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
		Answers: []ResourceRecord{
			{Name: "example.com", Class: ClassIN, Data: A{netip.MustParseAddr("1.2.3.4")}},
		},
	}
	orig := m.Header

	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	want := Header{ID: 9, Flags: 0x8180, QDCount: 1, ANCount: 1}
	if got.Header != want {
		t.Errorf("header = %+v, want %+v", got.Header, want)
	}
	if m.Header != orig {
		t.Errorf("Pack modified the caller's header: %+v, was %+v", m.Header, orig)
	}
}

func TestPackAppendsToPrefix(t *testing.T) {
	m := &Message{Header: Header{ID: 1}}
	plain, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.appendTo([]byte{0xaa, 0xbb})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "\xaa\xbb"+string(plain) {
		t.Errorf("got % x", got)
	}
}

func TestPackErrors(t *testing.T) {
	a := A{netip.MustParseAddr("1.2.3.4")}
	good := ResourceRecord{Name: "a", Class: ClassIN, Data: a}

	tests := []struct {
		name        string
		msg         *Message
		wantErr     error
		wantContext string
	}{
		{"nil message", nil, ErrNilMessage, ""},
		{
			"bad question",
			&Message{Questions: []Question{{Name: "a..b"}}},
			ErrEmptyLabel, "question[0]",
		},
		{
			"bad second answer",
			&Message{Answers: []ResourceRecord{good, {Name: "a..b", Data: a}}},
			ErrEmptyLabel, "answer[1]",
		},
		{
			"record without data",
			&Message{Authorities: []ResourceRecord{{Name: "a"}}},
			ErrNoData, "authority[0]",
		},
		{
			"bad data",
			&Message{Additionals: []ResourceRecord{{Name: "a", Data: A{}}}},
			ErrBadAddr, "additional[0]",
		},
		{
			"too many questions",
			&Message{Questions: make([]Question, 65536)},
			ErrTooMany, "",
		},
		{
			"too many answers",
			&Message{Answers: make([]ResourceRecord, 65536)},
			ErrTooMany, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.msg.Pack()
			if got != nil {
				t.Errorf("got % x, want nil on error", got)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantContext != "" && !strings.Contains(err.Error(), tt.wantContext) {
				t.Errorf("err = %q, want it to mention %q", err, tt.wantContext)
			}
		})
	}
}

func TestPackMaxCounts(t *testing.T) {
	m := &Message{Questions: make([]Question, 65535)}
	for i := range m.Questions {
		m.Questions[i] = Question{Name: "", Type: TypeA, Class: ClassIN}
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Questions) != 65535 || got.Header.QDCount != 65535 {
		t.Errorf("questions = %d, QDCount = %d", len(got.Questions), got.Header.QDCount)
	}
}
