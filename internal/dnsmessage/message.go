package dnsmessage

import (
	"fmt"
	"math"
)

// Smallest possible encodings, used to bound allocations from header counts:
// a question is a root name (1) plus QTYPE and QCLASS (4), and a record is a
// root name (1) plus the fixed fields.
const (
	minQuestionSize = 1 + 4
	minRecordSize   = 1 + resourceHeaderSize
)

// Message is a parsed DNS message (RFC 1035 §4.1).
type Message struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

// Unpack parses a complete DNS message. Bytes after the last record are
// ignored. Any failure is returned as a *ParseError naming the section and
// offset where parsing stopped, wrapping the underlying cause.
func Unpack(msg []byte) (*Message, error) {
	h, err := unpackHeader(msg)
	if err != nil {
		return nil, &ParseError{Section: "header", Offset: 0, Err: err}
	}
	m := &Message{Header: h}
	off := headerSize

	if m.Questions, off, err = unpackQuestions(msg, off, int(h.QDCount)); err != nil {
		return nil, err
	}
	if m.Answers, off, err = unpackRecords(msg, off, int(h.ANCount), "answer"); err != nil {
		return nil, err
	}
	if m.Authorities, off, err = unpackRecords(msg, off, int(h.NSCount), "authority"); err != nil {
		return nil, err
	}
	if m.Additionals, _, err = unpackRecords(msg, off, int(h.ARCount), "additional"); err != nil {
		return nil, err
	}
	return m, nil
}

// unpackQuestions decodes count questions starting at msg[off].
func unpackQuestions(msg []byte, off, count int) ([]Question, int, error) {
	if count == 0 {
		return nil, off, nil
	}
	// The count comes from the packet, so never trust it for allocation: only
	// reserve as many entries as could physically fit in the bytes left.
	qs := make([]Question, 0, min(count, (len(msg)-off)/minQuestionSize))
	for i := 0; i < count; i++ {
		q, next, err := unpackQuestion(msg, off)
		if err != nil {
			return nil, off, &ParseError{Section: fmt.Sprintf("question[%d]", i), Offset: off, Err: err}
		}
		qs = append(qs, q)
		off = next
	}
	return qs, off, nil
}

// unpackRecords decodes count resource records starting at msg[off]. section
// names the message section for error reporting.
func unpackRecords(msg []byte, off, count int, section string) ([]ResourceRecord, int, error) {
	if count == 0 {
		return nil, off, nil
	}
	rrs := make([]ResourceRecord, 0, min(count, (len(msg)-off)/minRecordSize))
	for i := 0; i < count; i++ {
		rr, next, err := unpackResourceRecord(msg, off)
		if err != nil {
			return nil, off, &ParseError{Section: fmt.Sprintf("%s[%d]", section, i), Offset: off, Err: err}
		}
		rrs = append(rrs, rr)
		off = next
	}
	return rrs, off, nil
}

// NewResponse returns a response to query with the given response code. It
// copies the ID, the opcode, the RD flag and the questions from the query and
// sets the QR flag. All other flags are left clear, and there are no records.
// The header counts are filled in by Pack.
func NewResponse(query *Message, rcode RCode) *Message {
	flags := flagQR | query.Header.Flags&(maskOpcode|flagRD) | uint16(rcode)&maskRCode
	return &Message{
		Header:    Header{ID: query.Header.ID, Flags: flags},
		Questions: append([]Question(nil), query.Questions...),
	}
}

// Truncate returns a copy of m for a response that is too large to send: the
// TC flag is set and all records are removed, while the rest of the header and
// the questions are kept. m itself is not modified.
func (m *Message) Truncate() *Message {
	h := m.Header
	h.Flags |= flagTC
	t := &Message{Header: h, Questions: append([]Question(nil), m.Questions...)}
	t.Header.QDCount = uint16(len(t.Questions))
	t.Header.ANCount, t.Header.NSCount, t.Header.ARCount = 0, 0, 0
	return t
}

// Pack encodes m in wire format. The header counts are derived from the
// lengths of the sections, so the counts stored in m.Header are ignored. Names
// are written uncompressed. On failure it returns nil and an error.
func (m *Message) Pack() ([]byte, error) {
	return m.appendTo(nil)
}

// appendTo appends the wire encoding of m to b and returns the extended
// slice. On failure it returns nil.
func (m *Message) appendTo(b []byte) ([]byte, error) {
	if m == nil {
		return nil, ErrNilMessage
	}
	for _, n := range []int{len(m.Questions), len(m.Answers), len(m.Authorities), len(m.Additionals)} {
		if n > math.MaxUint16 {
			return nil, ErrTooMany
		}
	}

	// h is a copy, so the caller's message is left untouched.
	h := m.Header
	h.QDCount = uint16(len(m.Questions))
	h.ANCount = uint16(len(m.Answers))
	h.NSCount = uint16(len(m.Authorities))
	h.ARCount = uint16(len(m.Additionals))
	b = h.appendTo(b)

	var err error
	for i, q := range m.Questions {
		if b, err = q.appendTo(b); err != nil {
			return nil, fmt.Errorf("question[%d]: %w", i, err)
		}
	}
	if b, err = appendRecords(b, m.Answers, "answer"); err != nil {
		return nil, err
	}
	if b, err = appendRecords(b, m.Authorities, "authority"); err != nil {
		return nil, err
	}
	if b, err = appendRecords(b, m.Additionals, "additional"); err != nil {
		return nil, err
	}
	return b, nil
}

// appendRecords appends each record in rrs to b. section names the message
// section for error reporting.
func appendRecords(b []byte, rrs []ResourceRecord, section string) ([]byte, error) {
	var err error
	for i, rr := range rrs {
		if b, err = rr.appendTo(b); err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", section, i, err)
		}
	}
	return b, nil
}
