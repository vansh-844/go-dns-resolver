package dnsmessage

import "encoding/binary"

// Question is an entry in the question section of a message (RFC 1035 §4.1.2).
type Question struct {
	Name  string
	Type  Type
	Class Class
}

// unpackQuestion decodes the question starting at msg[off]. msg must be the
// whole message. It returns the question and the offset just past it.
func unpackQuestion(msg []byte, off int) (Question, int, error) {
	name, next, err := unpackName(msg, off)
	if err != nil {
		return Question{}, off, err
	}
	// QTYPE and QCLASS are two bytes each.
	if next+4 > len(msg) {
		return Question{}, off, ErrShortBuffer
	}
	q := Question{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(msg[next : next+2])),
		Class: Class(binary.BigEndian.Uint16(msg[next+2 : next+4])),
	}
	return q, next + 4, nil
}

// appendTo appends the uncompressed wire encoding of q to b and returns the
// extended slice. On error it returns nil.
func (q Question) appendTo(b []byte) ([]byte, error) {
	b, err := appendName(b, q.Name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, uint16(q.Class))
	return b, nil
}
