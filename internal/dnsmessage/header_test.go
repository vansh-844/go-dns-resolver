package dnsmessage

import (
	"bytes"
	"errors"
	"testing"
)

// responseHeader is the header of a response to an A query for example.com:
// ID 0x1234, flags 0x8180 (QR, RD, RA), 1 question, 1 answer.
var responseHeader = []byte{
	0x12, 0x34, 0x81, 0x80,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
}

func TestUnpackHeader(t *testing.T) {
	tests := []struct {
		name    string
		msg     []byte
		want    Header
		wantErr error
	}{
		{
			name: "response header",
			msg:  responseHeader,
			want: Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1},
		},
		{
			name: "trailing bytes are ignored",
			msg:  append(append([]byte{}, responseHeader...), 0xde, 0xad),
			want: Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1},
		},
		{
			name: "all counts distinct",
			msg:  []byte{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6},
			want: Header{ID: 1, Flags: 2, QDCount: 3, ANCount: 4, NSCount: 5, ARCount: 6},
		},
		{
			name: "max values",
			msg:  bytes.Repeat([]byte{0xff}, headerSize),
			want: Header{ID: 0xffff, Flags: 0xffff, QDCount: 0xffff, ANCount: 0xffff, NSCount: 0xffff, ARCount: 0xffff},
		},
		{name: "nil", msg: nil, wantErr: ErrShortBuffer},
		{name: "empty", msg: []byte{}, wantErr: ErrShortBuffer},
		{name: "one byte short", msg: responseHeader[:headerSize-1], wantErr: ErrShortBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unpackHeader(tt.msg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("header = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHeaderFlagAccessors(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		check func(Header) bool
	}{
		{"QR", 0x8000, Header.IsResponse},
		{"AA", 0x0400, Header.Authoritative},
		{"TC", 0x0200, Header.Truncated},
		{"RD", 0x0100, Header.RecursionDesired},
		{"RA", 0x0080, Header.RecursionAvailable},
		{"AD", 0x0020, Header.AuthenticData},
		{"CD", 0x0010, Header.CheckingDisabled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check(Header{Flags: tt.flags}) {
				t.Errorf("flag %s not reported set for 0x%04x", tt.name, tt.flags)
			}
			if tt.check(Header{Flags: ^tt.flags}) {
				t.Errorf("flag %s reported set for 0x%04x", tt.name, ^tt.flags)
			}
		})
	}
}

func TestHeaderOpcodeAndRCode(t *testing.T) {
	tests := []struct {
		name       string
		flags      uint16
		wantOpcode uint8
		wantRCode  RCode
	}{
		{"zero", 0x0000, 0, 0},
		{"standard response", 0x8180, 0, 0},
		{"nxdomain", 0x8183, 0, 3},
		{"opcode 2 only", 0x1000, 2, 0},
		{"opcode 5 with rcode 2", 0x2802, 5, 2},
		{"all bits set", 0xffff, 15, 15},
		{"other flags do not leak", 0x87f0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Flags: tt.flags}
			if got := h.Opcode(); got != tt.wantOpcode {
				t.Errorf("Opcode() = %d, want %d", got, tt.wantOpcode)
			}
			if got := h.RCode(); got != tt.wantRCode {
				t.Errorf("RCode() = %d, want %d", got, tt.wantRCode)
			}
		})
	}
}

func TestHeaderAppendTo(t *testing.T) {
	h := Header{ID: 0x1234, Flags: 0x8180, QDCount: 1, ANCount: 1}

	t.Run("nil destination", func(t *testing.T) {
		if got := h.appendTo(nil); !bytes.Equal(got, responseHeader) {
			t.Errorf("got % x, want % x", got, responseHeader)
		}
	})

	t.Run("keeps existing prefix", func(t *testing.T) {
		prefix := []byte{0xaa, 0xbb}
		got := h.appendTo(prefix)
		want := append([]byte{0xaa, 0xbb}, responseHeader...)
		if !bytes.Equal(got, want) {
			t.Errorf("got % x, want % x", got, want)
		}
	})

	t.Run("big endian", func(t *testing.T) {
		got := Header{ID: 0x0102, ARCount: 0x0304}.appendTo(nil)
		if got[0] != 0x01 || got[1] != 0x02 || got[10] != 0x03 || got[11] != 0x04 {
			t.Errorf("not big-endian: % x", got)
		}
	})
}

func TestHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
	}{
		{"response header", responseHeader},
		{"all zero", make([]byte, headerSize)},
		{"all ones", bytes.Repeat([]byte{0xff}, headerSize)},
		{"reserved Z bit set", []byte{0, 1, 0x00, 0x40, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"distinct bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := unpackHeader(tt.msg)
			if err != nil {
				t.Fatalf("unpackHeader: %v", err)
			}
			if got := h.appendTo(nil); !bytes.Equal(got, tt.msg) {
				t.Errorf("round trip changed bytes:\n got % x\nwant % x", got, tt.msg)
			}
		})
	}
}
