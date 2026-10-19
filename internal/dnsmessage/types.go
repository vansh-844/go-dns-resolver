package dnsmessage

import "strconv"

// Type is a DNS resource record type (RFC 1035 §3.2.2).
type Type uint16

// Record types supported by this package.
const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
}

// String returns the standard mnemonic for t, or "TYPE<n>" if it is unknown.
func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// Class is a DNS class (RFC 1035 §3.2.4).
type Class uint16

// Classes supported by this package.
const (
	ClassIN Class = 1
)

// String returns the standard mnemonic for c, or "CLASS<n>" if it is unknown.
func (c Class) String() string {
	if c == ClassIN {
		return "IN"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// RCode is a DNS response code (RFC 1035 §4.1.1).
type RCode uint8

// Response codes supported by this package.
const (
	RCodeSuccess        RCode = 0 // no error
	RCodeFormatError    RCode = 1 // the query was malformed
	RCodeServerFailure  RCode = 2 // the server failed to process the query
	RCodeNameError      RCode = 3 // the name does not exist (NXDOMAIN)
	RCodeNotImplemented RCode = 4 // the kind of query is not supported
	RCodeRefused        RCode = 5 // the server refuses to answer
)

var rcodeNames = map[RCode]string{
	RCodeSuccess:        "NOERROR",
	RCodeFormatError:    "FORMERR",
	RCodeServerFailure:  "SERVFAIL",
	RCodeNameError:      "NXDOMAIN",
	RCodeNotImplemented: "NOTIMP",
	RCodeRefused:        "REFUSED",
}

// String returns the standard mnemonic for r, or "RCODE<n>" if it is unknown.
func (r RCode) String() string {
	if s, ok := rcodeNames[r]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(int(r))
}
