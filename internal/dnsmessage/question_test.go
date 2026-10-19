package dnsmessage

import (
	"bytes"
	"errors"
	"testing"
)

// exampleQuery is a query for example.com type A: 12-byte header followed by
// a 17-byte question.
var exampleQuery = []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
	"\x07example\x03com\x00\x00\x01\x00\x01")

func TestUnpackQuestion(t *testing.T) {
	tests := []struct {
		name     string
		msg      []byte
		off      int
		want     Question
		wantNext int
		wantErr  error
	}{
		{
			name:     "example.com A IN",
			msg:      exampleQuery,
			off:      headerSize,
			want:     Question{Name: "example.com", Type: TypeA, Class: ClassIN},
			wantNext: len(exampleQuery),
		},
		{
			name:     "compressed name",
			msg:      []byte("\x03com\x00\x04mail\xc0\x00\x00\x0f\x00\x01"),
			off:      5,
			want:     Question{Name: "mail.com", Type: TypeMX, Class: ClassIN},
			wantNext: 16,
		},
		{
			name:     "root name",
			msg:      []byte("\x00\x00\x02\x00\x01"),
			off:      0,
			want:     Question{Name: "", Type: TypeNS, Class: ClassIN},
			wantNext: 5,
		},
		{
			name:     "unknown type and class",
			msg:      []byte("\x03com\x00\x12\x34\x00\x63"),
			off:      0,
			want:     Question{Name: "com", Type: 0x1234, Class: 99},
			wantNext: 9,
		},
		{
			name:     "trailing data ignored",
			msg:      append(append([]byte{}, exampleQuery...), 0xff, 0xff),
			off:      headerSize,
			want:     Question{Name: "example.com", Type: TypeA, Class: ClassIN},
			wantNext: len(exampleQuery),
		},

		{name: "no question", msg: exampleQuery[:headerSize], off: headerSize, wantNext: headerSize, wantErr: ErrShortBuffer},
		{name: "type and class missing", msg: exampleQuery[:len(exampleQuery)-4], off: headerSize, wantNext: headerSize, wantErr: ErrShortBuffer},
		{name: "class missing", msg: exampleQuery[:len(exampleQuery)-2], off: headerSize, wantNext: headerSize, wantErr: ErrShortBuffer},
		{name: "one byte of class", msg: exampleQuery[:len(exampleQuery)-1], off: headerSize, wantNext: headerSize, wantErr: ErrShortBuffer},
		{name: "bad name", msg: []byte{0x40, 0, 0, 1, 0, 1}, off: 0, wantNext: 0, wantErr: ErrBadLabelType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := unpackQuestion(tt.msg, tt.off)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want || next != tt.wantNext {
				t.Errorf("got (%+v, %d), want (%+v, %d)", got, next, tt.want, tt.wantNext)
			}
		})
	}
}

func TestQuestionAppendTo(t *testing.T) {
	q := Question{Name: "example.com", Type: TypeA, Class: ClassIN}
	wire := exampleQuery[headerSize:]

	t.Run("nil destination", func(t *testing.T) {
		got, err := q.appendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, wire) {
			t.Errorf("got % x, want % x", got, wire)
		}
	})

	t.Run("keeps existing prefix", func(t *testing.T) {
		got, err := q.appendTo(exampleQuery[:headerSize:headerSize])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, exampleQuery) {
			t.Errorf("got % x, want % x", got, exampleQuery)
		}
	})

	t.Run("invalid name", func(t *testing.T) {
		got, err := Question{Name: "a..b", Type: TypeA, Class: ClassIN}.appendTo(nil)
		if !errors.Is(err, ErrEmptyLabel) {
			t.Errorf("err = %v, want %v", err, ErrEmptyLabel)
		}
		if got != nil {
			t.Errorf("got % x, want nil on error", got)
		}
	})
}

func TestQuestionRoundTrip(t *testing.T) {
	questions := []Question{
		{Name: "example.com", Type: TypeA, Class: ClassIN},
		{Name: "www.example.org", Type: TypeAAAA, Class: ClassIN},
		{Name: "", Type: TypeNS, Class: ClassIN},
		{Name: "example.com", Type: 0xffff, Class: 0xffff},
	}

	for _, q := range questions {
		t.Run(q.Name+"/"+q.Type.String(), func(t *testing.T) {
			wire, err := q.appendTo(nil)
			if err != nil {
				t.Fatalf("appendTo: %v", err)
			}
			got, next, err := unpackQuestion(wire, 0)
			if err != nil {
				t.Fatalf("unpackQuestion: %v", err)
			}
			if got != q {
				t.Errorf("got %+v, want %+v", got, q)
			}
			if next != len(wire) {
				t.Errorf("next = %d, want %d", next, len(wire))
			}
		})
	}
}

func TestTypeAndClassString(t *testing.T) {
	tests := []struct {
		got, want string
	}{
		{TypeA.String(), "A"},
		{TypeNS.String(), "NS"},
		{TypeCNAME.String(), "CNAME"},
		{TypeMX.String(), "MX"},
		{TypeTXT.String(), "TXT"},
		{TypeAAAA.String(), "AAAA"},
		{Type(99).String(), "TYPE99"},
		{ClassIN.String(), "IN"},
		{Class(3).String(), "CLASS3"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got %q, want %q", tt.got, tt.want)
		}
	}
}
