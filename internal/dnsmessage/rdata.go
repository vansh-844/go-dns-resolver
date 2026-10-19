package dnsmessage

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

// ResourceData is the type-specific payload (RDATA) of a resource record.
type ResourceData interface {
	// Type returns the record type this data belongs to.
	Type() Type

	// appendTo appends the uncompressed wire encoding of the data to b.
	appendTo(b []byte) ([]byte, error)
}

// A is the data of an A record: an IPv4 address.
type A struct {
	Addr netip.Addr
}

// Type implements ResourceData.
func (A) Type() Type { return TypeA }

func (r A) appendTo(b []byte) ([]byte, error) {
	if !r.Addr.Is4() {
		return nil, ErrBadAddr
	}
	a := r.Addr.As4()
	return append(b, a[:]...), nil
}

// AAAA is the data of an AAAA record: an IPv6 address.
type AAAA struct {
	Addr netip.Addr
}

// Type implements ResourceData.
func (AAAA) Type() Type { return TypeAAAA }

func (r AAAA) appendTo(b []byte) ([]byte, error) {
	if !r.Addr.Is6() {
		return nil, ErrBadAddr
	}
	a := r.Addr.As16()
	return append(b, a[:]...), nil
}

// NS is the data of an NS record: the name of an authoritative nameserver.
type NS struct {
	Host string
}

// Type implements ResourceData.
func (NS) Type() Type { return TypeNS }

func (r NS) appendTo(b []byte) ([]byte, error) { return appendName(b, r.Host) }

// CNAME is the data of a CNAME record: the canonical name an alias points to.
type CNAME struct {
	Target string
}

// Type implements ResourceData.
func (CNAME) Type() Type { return TypeCNAME }

func (r CNAME) appendTo(b []byte) ([]byte, error) { return appendName(b, r.Target) }

// MX is the data of an MX record: a mail server and its priority (lower
// preference values are tried first).
type MX struct {
	Preference uint16
	Host       string
}

// Type implements ResourceData.
func (MX) Type() Type { return TypeMX }

func (r MX) appendTo(b []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, r.Preference)
	return appendName(b, r.Host)
}

// TXT is the data of a TXT record: one or more strings of at most 255 bytes.
// An empty Strings slice is encoded as a single empty string.
type TXT struct {
	Strings []string
}

// Type implements ResourceData.
func (TXT) Type() Type { return TypeTXT }

func (r TXT) appendTo(b []byte) ([]byte, error) {
	if len(r.Strings) == 0 {
		return append(b, 0), nil
	}
	for _, s := range r.Strings {
		if len(s) > maxTXTStringLen {
			return nil, ErrTXTStringTooLong
		}
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b, nil
}

// Unknown holds the raw data of a record whose type this package does not
// decode, so that such records can still be passed through unchanged.
type Unknown struct {
	RRType Type
	Data   []byte
}

// Type implements ResourceData.
func (r Unknown) Type() Type { return r.RRType }

func (r Unknown) appendTo(b []byte) ([]byte, error) { return append(b, r.Data...), nil }

const maxTXTStringLen = 255

// unpackRData decodes the RDATA of a record of type t occupying msg[off:end].
// msg must be the whole message, since names inside RDATA may be compressed.
// It returns an error if the data is malformed or does not fill exactly the
// range given by the record's RDLENGTH.
func unpackRData(msg []byte, off, end int, t Type) (ResourceData, error) {
	length := end - off

	switch t {
	case TypeA:
		if length != 4 {
			return nil, ErrBadRDLength
		}
		return A{Addr: netip.AddrFrom4([4]byte(msg[off:end]))}, nil

	case TypeAAAA:
		if length != 16 {
			return nil, ErrBadRDLength
		}
		return AAAA{Addr: netip.AddrFrom16([16]byte(msg[off:end]))}, nil

	case TypeNS:
		host, err := unpackRDataName(msg, off, end)
		if err != nil {
			return nil, err
		}
		return NS{Host: host}, nil

	case TypeCNAME:
		target, err := unpackRDataName(msg, off, end)
		if err != nil {
			return nil, err
		}
		return CNAME{Target: target}, nil

	case TypeMX:
		if length < 3 { // preference plus at least the root name
			return nil, ErrBadRDLength
		}
		host, err := unpackRDataName(msg, off+2, end)
		if err != nil {
			return nil, err
		}
		return MX{Preference: binary.BigEndian.Uint16(msg[off : off+2]), Host: host}, nil

	case TypeTXT:
		if length == 0 {
			return nil, ErrBadRDLength
		}
		var strs []string
		for p := off; p < end; {
			n := int(msg[p])
			p++
			if p+n > end {
				return nil, ErrBadRDLength
			}
			strs = append(strs, string(msg[p:p+n]))
			p += n
		}
		return TXT{Strings: strs}, nil

	default:
		// Copy so the result does not alias the caller's buffer.
		return Unknown{RRType: t, Data: bytes.Clone(msg[off:end])}, nil
	}
}

// unpackRDataName decodes a name at msg[off] that must end exactly at end.
func unpackRDataName(msg []byte, off, end int) (string, error) {
	name, next, err := unpackName(msg, off)
	if err != nil {
		return "", err
	}
	if next != end {
		return "", ErrBadRDLength
	}
	return name, nil
}
