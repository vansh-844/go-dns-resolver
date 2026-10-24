package dnsmessage

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// soaFixed holds an SOA's five 32-bit fields: serial 1, refresh 2, retry 3,
// expire 4 and minimum 5.
const soaFixed = "\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"

func TestUnpackRData(t *testing.T) {
	ip6Loopback := append(make([]byte, 15), 1)
	soa := SOA{"ns.com", "host.com", 1, 2, 3, 4, 5}

	tests := []struct {
		name    string
		msg     []byte
		off     int
		end     int // 0 means len(msg)
		typ     Type
		want    ResourceData
		wantErr error
	}{
		{"A", []byte{1, 2, 3, 4}, 0, 0, TypeA, A{netip.MustParseAddr("1.2.3.4")}, nil},
		{"A too short", []byte{1, 2, 3}, 0, 0, TypeA, nil, ErrBadRDLength},
		{"A too long", []byte{1, 2, 3, 4, 5}, 0, 0, TypeA, nil, ErrBadRDLength},
		{"A empty", nil, 0, 0, TypeA, nil, ErrBadRDLength},

		{"AAAA", ip6Loopback, 0, 0, TypeAAAA, AAAA{netip.MustParseAddr("::1")}, nil},
		{"AAAA too short", []byte{1, 2, 3, 4}, 0, 0, TypeAAAA, nil, ErrBadRDLength},
		{"AAAA too long", make([]byte, 17), 0, 0, TypeAAAA, nil, ErrBadRDLength},

		{"NS", []byte("\x02ns\x07example\x03com\x00"), 0, 0, TypeNS, NS{"ns.example.com"}, nil},
		{
			"CNAME with pointer",
			[]byte("\x07example\x03com\x00\x03www\xc0\x00"), 13, 19, TypeCNAME,
			CNAME{"www.example.com"}, nil,
		},
		{"CNAME root", []byte{0}, 0, 0, TypeCNAME, CNAME{""}, nil},
		{"NS shorter than RDLENGTH", []byte("\x03com\x00\xff"), 0, 0, TypeNS, nil, ErrBadRDLength},
		{"NS longer than RDLENGTH", []byte("\x03com\x00"), 0, 3, TypeNS, nil, ErrBadRDLength},
		{"NS empty", nil, 0, 0, TypeNS, nil, ErrShortBuffer},
		{"NS bad name", []byte{0x40, 0}, 0, 0, TypeNS, nil, ErrBadLabelType},

		{"MX", []byte("\x00\x0a\x04mail\x03com\x00"), 0, 0, TypeMX, MX{10, "mail.com"}, nil},
		{
			"MX with pointer",
			[]byte("\x03com\x00\x00\x05\x04mail\xc0\x00"), 5, 14, TypeMX,
			MX{5, "mail.com"}, nil,
		},
		{"MX preference only", []byte{0, 10}, 0, 0, TypeMX, nil, ErrBadRDLength},
		{"MX trailing bytes", []byte("\x00\x0a\x00\xff"), 0, 0, TypeMX, nil, ErrBadRDLength},

		{"PTR", []byte("\x03one\x03one\x03one\x03one\x00"), 0, 0, TypePTR, PTR{"one.one.one.one"}, nil},
		{"PTR trailing bytes", []byte("\x03com\x00\xff"), 0, 0, TypePTR, nil, ErrBadRDLength},

		{"SOA", []byte("\x02ns\x03com\x00\x04host\x03com\x00" + soaFixed), 0, 0, TypeSOA, soa, nil},
		{
			"SOA with pointers",
			[]byte("\x03com\x00\x02ns\xc0\x00\x04host\xc0\x00" + soaFixed), 5, 0, TypeSOA,
			soa, nil,
		},
		{"SOA root names", []byte("\x00\x00" + soaFixed), 0, 0, TypeSOA, SOA{"", "", 1, 2, 3, 4, 5}, nil},
		{"SOA empty", nil, 0, 0, TypeSOA, nil, ErrBadRDLength},
		{"SOA names only", []byte("\x02ns\x03com\x00\x04host\x03com\x00"), 0, 0, TypeSOA, nil, ErrBadRDLength},
		{"SOA fixed fields short", []byte("\x00\x00" + soaFixed[:19]), 0, 0, TypeSOA, nil, ErrBadRDLength},
		{"SOA trailing byte", []byte("\x00\x00" + soaFixed + "\xff"), 0, 0, TypeSOA, nil, ErrBadRDLength},
		{"SOA MName crosses end", []byte("\x02ns\x03com\x00"), 0, 3, TypeSOA, nil, ErrBadRDLength},
		{"SOA bad name", []byte("\x40\x00" + soaFixed), 0, 0, TypeSOA, nil, ErrBadLabelType},

		{"SRV", []byte("\x00\x0a\x00\x05\x14\x95\x03sip\x03com\x00"), 0, 0, TypeSRV, SRV{10, 5, 5269, "sip.com"}, nil},
		{
			"SRV with pointer",
			[]byte("\x03com\x00\x00\x01\x00\x02\x00\x03\x03sip\xc0\x00"), 5, 0, TypeSRV,
			SRV{1, 2, 3, "sip.com"}, nil,
		},
		{"SRV fixed fields only", []byte{0, 1, 0, 2, 0, 3}, 0, 0, TypeSRV, nil, ErrBadRDLength},
		{"SRV trailing bytes", []byte("\x00\x01\x00\x02\x00\x03\x00\xff"), 0, 0, TypeSRV, nil, ErrBadRDLength},

		{"TXT two strings", []byte("\x05hello\x05world"), 0, 0, TypeTXT, TXT{[]string{"hello", "world"}}, nil},
		{"TXT empty string", []byte{0}, 0, 0, TypeTXT, TXT{[]string{""}}, nil},
		{"TXT no data", nil, 0, 0, TypeTXT, nil, ErrBadRDLength},
		{"TXT truncated string", []byte("\x05abc"), 0, 0, TypeTXT, nil, ErrBadRDLength},
		{"TXT string crosses end", []byte("\x03abc\x05de"), 0, 0, TypeTXT, nil, ErrBadRDLength},

		{"unknown", []byte{1, 2, 3}, 0, 0, 99, Unknown{99, []byte{1, 2, 3}}, nil},
		{"unknown empty", []byte{}, 0, 0, 99, Unknown{99, []byte{}}, nil},

		{"uses off and end", []byte{9, 9, 1, 2, 3, 4, 9}, 2, 6, TypeA, A{netip.MustParseAddr("1.2.3.4")}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			end := tt.end
			if end == 0 {
				end = len(tt.msg)
			}
			got, err := unpackRData(tt.msg, tt.off, end, tt.typ)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestUnpackRDataUnknownDoesNotAliasMessage(t *testing.T) {
	msg := []byte{1, 2, 3}
	got, err := unpackRData(msg, 0, len(msg), 99)
	if err != nil {
		t.Fatal(err)
	}
	msg[0] = 0xff
	if u := got.(Unknown); u.Data[0] != 1 {
		t.Errorf("Unknown data changed with the message: % x", u.Data)
	}
}

func TestRDataAppendTo(t *testing.T) {
	tests := []struct {
		name    string
		data    ResourceData
		want    []byte
		wantErr error
	}{
		{"A", A{netip.MustParseAddr("1.2.3.4")}, []byte{1, 2, 3, 4}, nil},
		{"A with IPv6", A{netip.MustParseAddr("::1")}, nil, ErrBadAddr},
		{"A zero address", A{}, nil, ErrBadAddr},

		{"AAAA", AAAA{netip.MustParseAddr("::1")}, append(make([]byte, 15), 1), nil},
		{"AAAA with IPv4", AAAA{netip.MustParseAddr("1.2.3.4")}, nil, ErrBadAddr},
		{"AAAA zero address", AAAA{}, nil, ErrBadAddr},

		{"NS", NS{"ns.example.com"}, []byte("\x02ns\x07example\x03com\x00"), nil},
		{"NS invalid name", NS{"a..b"}, nil, ErrEmptyLabel},
		{"CNAME", CNAME{"www.example.com."}, []byte("\x03www\x07example\x03com\x00"), nil},
		{"MX", MX{10, "mail.com"}, []byte("\x00\x0a\x04mail\x03com\x00"), nil},
		{"MX invalid name", MX{10, "a..b"}, nil, ErrEmptyLabel},
		{"PTR", PTR{"one.one.one.one"}, []byte("\x03one\x03one\x03one\x03one\x00"), nil},
		{"PTR invalid name", PTR{"a..b"}, nil, ErrEmptyLabel},

		{
			"SOA", SOA{"ns.com", "host.com", 1, 2, 3, 4, 5},
			[]byte("\x02ns\x03com\x00\x04host\x03com\x00" + soaFixed), nil,
		},
		{"SOA invalid MName", SOA{MName: "a..b"}, nil, ErrEmptyLabel},
		{"SOA invalid RName", SOA{RName: "a..b"}, nil, ErrEmptyLabel},

		{"SRV", SRV{10, 5, 5269, "sip.com"}, []byte("\x00\x0a\x00\x05\x14\x95\x03sip\x03com\x00"), nil},
		{"SRV invalid name", SRV{Target: "a..b"}, nil, ErrEmptyLabel},

		{"TXT", TXT{[]string{"hello", "world"}}, []byte("\x05hello\x05world"), nil},
		{"TXT no strings", TXT{}, []byte{0}, nil},
		{"TXT string of 255", TXT{[]string{strings.Repeat("a", 255)}}, append([]byte{255}, bytes.Repeat([]byte("a"), 255)...), nil},
		{"TXT string of 256", TXT{[]string{strings.Repeat("a", 256)}}, nil, ErrTXTStringTooLong},

		{"Unknown", Unknown{99, []byte{1, 2, 3}}, []byte{1, 2, 3}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.data.appendTo(nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("got % x, want % x", got, tt.want)
			}
		})
	}
}

func TestRDataTypes(t *testing.T) {
	tests := []struct {
		data ResourceData
		want Type
	}{
		{A{}, TypeA},
		{AAAA{}, TypeAAAA},
		{NS{}, TypeNS},
		{CNAME{}, TypeCNAME},
		{SOA{}, TypeSOA},
		{PTR{}, TypePTR},
		{MX{}, TypeMX},
		{TXT{}, TypeTXT},
		{SRV{}, TypeSRV},
		{Unknown{RRType: 99}, 99},
	}
	for _, tt := range tests {
		if got := tt.data.Type(); got != tt.want {
			t.Errorf("%T.Type() = %v, want %v", tt.data, got, tt.want)
		}
	}
}

// TestSOACompressedNamesSurviveRepack is the case that made decoding SOA
// necessary: an NXDOMAIN reply whose SOA names point back into the question.
// Kept as raw bytes, the pointers would be wrong in the re-packed message.
func TestSOACompressedNamesSurviveRepack(t *testing.T) {
	msg := []byte("" +
		"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00" + // header: NXDOMAIN, 1 question, 1 authority
		"\x07example\x03com\x00\x00\x01\x00\x01" + // question at offset 12: example.com A IN
		"\xc0\x0c\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x20" + // example.com SOA IN, TTL 3600, RDLENGTH 32
		"\x02ns\xc0\x0c" + "\x04host\xc0\x0c" + soaFixed) // ns.example.com, host.example.com

	want := SOA{"ns.example.com", "host.example.com", 1, 2, 3, 4, 5}

	m, err := Unpack(msg)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(m.Authorities) != 1 || m.Authorities[0].Data != want {
		t.Fatalf("authorities = %#v, want one with %#v", m.Authorities, want)
	}

	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	again, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack of re-packed message: %v", err)
	}
	if !reflect.DeepEqual(again.Authorities, m.Authorities) {
		t.Errorf("authorities after re-pack = %#v, want %#v", again.Authorities, m.Authorities)
	}
}
