package dnsmessage

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAppendName(t *testing.T) {
	label63 := strings.Repeat("a", 63)

	tests := []struct {
		name    string
		in      string
		want    []byte
		wantErr error
	}{
		{"plain", "example.com", []byte("\x07example\x03com\x00"), nil},
		{"single label", "com", []byte("\x03com\x00"), nil},
		{"trailing dot", "example.com.", []byte("\x07example\x03com\x00"), nil},
		{"root dot", ".", []byte{0}, nil},
		{"root empty", "", []byte{0}, nil},
		{"case preserved", "ExAmple.COM", []byte("\x07ExAmple\x03COM\x00"), nil},
		{"label of 63", label63, append(append([]byte{63}, label63...), 0), nil},
		// 3 labels of 63 + one of 61: 3*64 + 62 + 1 = 255 bytes encoded.
		{"name of exactly 255", strings.Join([]string{label63, label63, label63, strings.Repeat("a", 61)}, "."), nil, nil},

		{"empty label in middle", "a..b", nil, ErrEmptyLabel},
		{"leading dot", ".a", nil, ErrEmptyLabel},
		{"two trailing dots", "a..", nil, ErrEmptyLabel},
		{"label of 64", label63 + "a", nil, ErrLabelTooLong},
		{"name of 256", strings.Join([]string{label63, label63, label63, strings.Repeat("a", 62)}, "."), nil, ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appendName(nil, tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.name == "name of exactly 255" {
				if len(got) != 255 {
					t.Errorf("encoded length = %d, want 255", len(got))
				}
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("got % x, want % x", got, tt.want)
			}
		})
	}
}

func TestAppendNameKeepsPrefix(t *testing.T) {
	got, err := appendName([]byte{0xaa, 0xbb}, "com")
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("\xaa\xbb\x03com\x00"); !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

func TestUnpackName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// Four 63-byte labels encode to 257 bytes, over the 255 limit.
	tooLong := append(bytes.Repeat(append([]byte{63}, label63...), 4), 0)

	tests := []struct {
		name     string
		msg      []byte
		off      int
		want     string
		wantNext int
		wantErr  error
	}{
		{"plain", []byte("\x07example\x03com\x00"), 0, "example.com", 13, nil},
		{"root", []byte{0}, 0, "", 1, nil},
		{"non-zero offset", []byte("\xff\xff\x03com\x00"), 2, "com", 7, nil},
		{"trailing data ignored", []byte("\x03com\x00\xff\xff"), 0, "com", 5, nil},
		{"case preserved", []byte("\x03CoM\x00"), 0, "CoM", 5, nil},

		// Compression: next must point just past the first pointer.
		{"pointer only", []byte("\x03com\x00\xc0\x00"), 5, "com", 7, nil},
		{"label then pointer", []byte("\x07example\x03com\x00\x04mail\xc0\x00"), 13, "mail.example.com", 20, nil},
		{"pointer into middle of name", []byte("\x07example\x03com\x00\xc0\x08"), 13, "com", 15, nil},
		{"pointer chain", []byte("\x03com\x00\x03foo\xc0\x00\xc0\x05"), 11, "foo.com", 13, nil},
		{"pointer to root", []byte("\x00\xc0\x00"), 1, "", 3, nil},

		{"empty message", nil, 0, "", 0, ErrShortBuffer},
		{"offset past end", []byte{0}, 5, "", 5, ErrShortBuffer},
		{"negative offset", []byte{0}, -1, "", -1, ErrShortBuffer},
		{"truncated label", []byte("\x05abc"), 0, "", 0, ErrShortBuffer},
		{"missing terminator", []byte("\x03abc"), 0, "", 0, ErrShortBuffer},
		{"truncated pointer", []byte{0xc0}, 0, "", 0, ErrShortBuffer},
		{"pointer past end", []byte{0xc0, 0x10}, 0, "", 0, ErrBadPointer},

		{"self pointer", []byte{0xc0, 0x00}, 0, "", 0, ErrPointerLoop},
		{"forward pointer", []byte{0xc0, 0x04, 0, 0, 0}, 0, "", 0, ErrBadPointer},
		{"mutual loop", []byte{0x01, 'a', 0xc0, 0x04, 0x01, 'b', 0xc0, 0x00}, 4, "", 4, ErrBadPointer},
		{"reserved label type 01", []byte{0x40, 0}, 0, "", 0, ErrBadLabelType},
		{"reserved label type 10", []byte{0x80, 0}, 0, "", 0, ErrBadLabelType},
		{"name too long", tooLong, 0, "", 0, ErrNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, next, err := unpackName(tt.msg, tt.off)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want || next != tt.wantNext {
				t.Errorf("got (%q, %d), want (%q, %d)", got, next, tt.want, tt.wantNext)
			}
		})
	}
}

func TestNameRoundTrip(t *testing.T) {
	names := []string{"", "com", "example.com", "www.example.co.uk", "a.b.c.d.e.f", "ExAmple.COM"}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			wire, err := appendName(nil, name)
			if err != nil {
				t.Fatalf("appendName: %v", err)
			}
			got, next, err := unpackName(wire, 0)
			if err != nil {
				t.Fatalf("unpackName: %v", err)
			}
			if got != name {
				t.Errorf("name = %q, want %q", got, name)
			}
			if next != len(wire) {
				t.Errorf("next = %d, want %d", next, len(wire))
			}
		})
	}
}
