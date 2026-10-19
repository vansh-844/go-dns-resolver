package dnsmessage

import (
	"encoding/binary"
)

// headerSize is the fixed length in bytes of a DNS message header.
const headerSize = 12

// Bit masks for the 16-bit Header.Flags field (RFC 1035 §4.1.1, RFC 4035 §3).
// Bit 15 is the most significant bit.
const (
	flagQR     uint16 = 1 << 15 // 0 = query, 1 = response
	maskOpcode uint16 = 0xF << 11
	flagAA     uint16 = 1 << 10 // authoritative answer
	flagTC     uint16 = 1 << 9  // truncated
	flagRD     uint16 = 1 << 8  // recursion desired
	flagRA     uint16 = 1 << 7  // recursion available
	flagAD     uint16 = 1 << 5  // authentic data (DNSSEC)
	flagCD     uint16 = 1 << 4  // checking disabled (DNSSEC)
	maskRCode  uint16 = 0xF

	shiftOpcode = 11
)

// OpcodeQuery is the opcode of a standard query.
const OpcodeQuery uint8 = 0

// Header is the fixed 12-byte header of a DNS message (RFC 1035 §4.1.1).
//
// Flags holds the raw 16 flag bits so that unpacking and repacking a header
// never loses information, including reserved bits. Use the accessor methods
// to read individual flags.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// IsResponse reports whether the QR bit is set.
func (h Header) IsResponse() bool { return h.Flags&flagQR != 0 }

// Opcode returns the 4-bit operation code (0 is a standard query).
func (h Header) Opcode() uint8 { return uint8((h.Flags & maskOpcode) >> shiftOpcode) }

// Authoritative reports whether the AA bit is set.
func (h Header) Authoritative() bool { return h.Flags&flagAA != 0 }

// Truncated reports whether the TC bit is set.
func (h Header) Truncated() bool { return h.Flags&flagTC != 0 }

// RecursionDesired reports whether the RD bit is set.
func (h Header) RecursionDesired() bool { return h.Flags&flagRD != 0 }

// RecursionAvailable reports whether the RA bit is set.
func (h Header) RecursionAvailable() bool { return h.Flags&flagRA != 0 }

// AuthenticData reports whether the AD bit is set.
func (h Header) AuthenticData() bool { return h.Flags&flagAD != 0 }

// CheckingDisabled reports whether the CD bit is set.
func (h Header) CheckingDisabled() bool { return h.Flags&flagCD != 0 }

// RCode returns the 4-bit response code (0 is NOERROR).
func (h Header) RCode() RCode { return RCode(h.Flags & maskRCode) }

// unpackHeader decodes the header at the start of msg.
func unpackHeader(msg []byte) (Header, error) {
	if len(msg) < headerSize {
		return Header{}, ErrShortBuffer
	}
	return Header{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}, nil
}

// appendTo appends the 12-byte wire encoding of h to b and returns the
// extended slice.
func (h Header) appendTo(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, h.ID)
	b = binary.BigEndian.AppendUint16(b, h.Flags)
	b = binary.BigEndian.AppendUint16(b, h.QDCount)
	b = binary.BigEndian.AppendUint16(b, h.ANCount)
	b = binary.BigEndian.AppendUint16(b, h.NSCount)
	b = binary.BigEndian.AppendUint16(b, h.ARCount)
	return b
}
