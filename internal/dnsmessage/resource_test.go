package dnsmessage

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// exampleAnswer is the answer record of a response to an A query for
// example.com. Its name is a pointer to offset 12, the question.
var exampleAnswer = []byte("\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22")

// exampleResponse is a full response: header, question, then exampleAnswer.
func exampleResponse() []byte {
	msg := append([]byte{}, responseHeader...)
	msg = append(msg, exampleQuery[headerSize:]...)
	return append(msg, exampleAnswer...)
}

func TestUnpackResourceRecord(t *testing.T) {
	msg := exampleResponse()
	const answerOff = headerSize + 17

	t.Run("compressed answer", func(t *testing.T) {
		got, next, err := unpackResourceRecord(msg, answerOff)
		if err != nil {
			t.Fatal(err)
		}
		want := ResourceRecord{
			Name:  "example.com",
			Class: ClassIN,
			TTL:   300,
			Data:  A{netip.MustParseAddr("93.184.216.34")},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if next != len(msg) {
			t.Errorf("next = %d, want %d", next, len(msg))
		}
	})

	t.Run("trailing data ignored", func(t *testing.T) {
		withTail := append(append([]byte{}, msg...), 0xff, 0xff)
		_, next, err := unpackResourceRecord(withTail, answerOff)
		if err != nil {
			t.Fatal(err)
		}
		if next != len(msg) {
			t.Errorf("next = %d, want %d", next, len(msg))
		}
	})

	t.Run("unknown type keeps raw data", func(t *testing.T) {
		rec := []byte("\x03com\x00\x12\x34\x00\x01\x00\x00\x00\x07\x00\x02\xab\xcd")
		got, next, err := unpackResourceRecord(rec, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := ResourceRecord{Name: "com", Class: ClassIN, TTL: 7, Data: Unknown{0x1234, []byte{0xab, 0xcd}}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if got.Type() != 0x1234 || next != len(rec) {
			t.Errorf("Type() = %v, next = %d", got.Type(), next)
		}
	})

	t.Run("max TTL", func(t *testing.T) {
		rec := []byte("\x00\x00\x63\x00\x01\xff\xff\xff\xff\x00\x00")
		got, _, err := unpackResourceRecord(rec, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got.TTL != 0xffffffff {
			t.Errorf("TTL = %d", got.TTL)
		}
	})

	errTests := []struct {
		name    string
		msg     []byte
		wantErr error
	}{
		{"nothing at offset", msg[:answerOff], ErrShortBuffer},
		{"name only", msg[:answerOff+2], ErrShortBuffer},
		{"fixed fields cut short", msg[:answerOff+2+9], ErrShortBuffer},
		{"RDATA missing", msg[:answerOff+2+10], ErrShortBuffer},
		{"RDATA cut short", msg[:len(msg)-1], ErrShortBuffer},
		{"bad name", []byte{0x40, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0}, ErrBadLabelType},
		{
			"RDLENGTH disagrees with type",
			[]byte("\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x03\x01\x02\x03"),
			ErrBadRDLength,
		},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			off := answerOff
			if tt.name == "bad name" || tt.name == "RDLENGTH disagrees with type" {
				off = 0
			}
			got, next, err := unpackResourceRecord(tt.msg, off)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if next != off || !reflect.DeepEqual(got, ResourceRecord{}) {
				t.Errorf("got (%+v, %d), want zero record and next = %d", got, next, off)
			}
		})
	}
}

func TestResourceRecordAppendTo(t *testing.T) {
	rr := ResourceRecord{
		Name:  "example.com",
		Class: ClassIN,
		TTL:   300,
		Data:  A{netip.MustParseAddr("93.184.216.34")},
	}
	wire := []byte("\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22")

	t.Run("nil destination", func(t *testing.T) {
		got, err := rr.appendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, wire) {
			t.Errorf("got % x, want % x", got, wire)
		}
	})

	t.Run("RDLENGTH is correct after a prefix", func(t *testing.T) {
		got, err := rr.appendTo([]byte{0xaa, 0xbb, 0xcc})
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte{0xaa, 0xbb, 0xcc}, wire...)
		if !bytes.Equal(got, want) {
			t.Errorf("got % x, want % x", got, want)
		}
	})

	t.Run("RDATA of exactly 65535", func(t *testing.T) {
		big := ResourceRecord{Name: "a", Class: ClassIN, Data: Unknown{99, make([]byte, 0xFFFF)}}
		got, err := big.appendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		back, _, err := unpackResourceRecord(got, 0)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(back.Data.(Unknown).Data); n != 0xFFFF {
			t.Errorf("RDATA length after round trip = %d", n)
		}
	})

	errTests := []struct {
		name    string
		rr      ResourceRecord
		wantErr error
	}{
		{"no data", ResourceRecord{Name: "a", Class: ClassIN}, ErrNoData},
		{"bad name", ResourceRecord{Name: "a..b", Class: ClassIN, Data: A{netip.MustParseAddr("1.2.3.4")}}, ErrEmptyLabel},
		{"bad data", ResourceRecord{Name: "a", Class: ClassIN, Data: A{}}, ErrBadAddr},
		{"RDATA of 65536", ResourceRecord{Name: "a", Class: ClassIN, Data: Unknown{99, make([]byte, 0x10000)}}, ErrTooMany},
	}
	for _, tt := range errTests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.rr.appendTo(nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != nil {
				t.Errorf("got % x, want nil on error", got)
			}
		})
	}
}

func TestResourceRecordRoundTrip(t *testing.T) {
	records := []ResourceRecord{
		{Name: "example.com", Class: ClassIN, TTL: 300, Data: A{netip.MustParseAddr("93.184.216.34")}},
		{Name: "example.com", Class: ClassIN, TTL: 60, Data: AAAA{netip.MustParseAddr("2606:2800:220:1::1")}},
		{Name: "example.com", Class: ClassIN, TTL: 3600, Data: NS{"ns1.example.com"}},
		{Name: "www.example.com", Class: ClassIN, TTL: 30, Data: CNAME{"example.com"}},
		{Name: "example.com", Class: ClassIN, TTL: 300, Data: MX{10, "mail.example.com"}},
		{Name: "example.com", Class: ClassIN, TTL: 300, Data: TXT{[]string{"v=spf1 -all", "second"}}},
		{Name: "example.com", Class: ClassIN, TTL: 300, Data: Unknown{0x1234, []byte{1, 2, 3}}},
		{Name: "", Class: ClassIN, TTL: 0, Data: A{netip.MustParseAddr("0.0.0.0")}},
	}

	for _, rr := range records {
		t.Run(rr.Name+"/"+rr.Type().String(), func(t *testing.T) {
			wire, err := rr.appendTo(nil)
			if err != nil {
				t.Fatalf("appendTo: %v", err)
			}
			got, next, err := unpackResourceRecord(wire, 0)
			if err != nil {
				t.Fatalf("unpackResourceRecord: %v", err)
			}
			if !reflect.DeepEqual(got, rr) {
				t.Errorf("got %+v, want %+v", got, rr)
			}
			if next != len(wire) {
				t.Errorf("next = %d, want %d", next, len(wire))
			}
		})
	}
}

func TestResourceRecordType(t *testing.T) {
	if got := (ResourceRecord{}).Type(); got != 0 {
		t.Errorf("Type() with nil data = %v, want 0", got)
	}
	if got := (ResourceRecord{Data: MX{}}).Type(); got != TypeMX {
		t.Errorf("Type() = %v, want MX", got)
	}
}
