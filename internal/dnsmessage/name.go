package dnsmessage

import "strings"

const (
	maxLabelLen = 63
	maxNameLen  = 255 // limit on the encoded (wire) length of a name

	labelTypeMask    = 0xC0 // top two bits of a label's first byte
	labelTypeNormal  = 0x00
	labelTypePointer = 0xC0
)

// appendName appends the uncompressed wire encoding of name to b.
// A single trailing dot is allowed, and "" and "." both encode the root.
func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil
	}
	// Each label costs one length byte, plus one terminating zero byte.
	if len(name)+2 > maxNameLen {
		return nil, ErrNameTooLong
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return nil, ErrEmptyLabel
		}
		if len(label) > maxLabelLen {
			return nil, ErrLabelTooLong
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

// unpackName decodes the possibly compressed name starting at msg[off].
// msg must be the whole DNS message, since compression pointers are offsets
// from its start. It returns the name without a trailing dot (the root name
// is ""), and the offset just past the name in the original position: after
// the terminating zero byte, or after the first pointer if there was one.
func unpackName(msg []byte, off int) (name string, next int, err error) {
	var sb strings.Builder
	next = -1    // set when the first pointer is followed
	wireLen := 1 // the terminating zero byte
	cur := off   // where we are currently reading

	for {
		if cur < 0 || cur >= len(msg) {
			return "", off, ErrShortBuffer
		}
		c := msg[cur]

		switch c & labelTypeMask {
		case labelTypeNormal:
			if c == 0 { // root label: end of name
				if next < 0 {
					next = cur + 1
				}
				return sb.String(), next, nil
			}
			n := int(c)
			if cur+1+n > len(msg) {
				return "", off, ErrShortBuffer
			}
			wireLen += 1 + n
			if wireLen > maxNameLen {
				return "", off, ErrNameTooLong
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(msg[cur+1 : cur+1+n])
			cur += 1 + n

		case labelTypePointer:
			if cur+2 > len(msg) {
				return "", off, ErrShortBuffer
			}
			target := int(c&^labelTypeMask)<<8 | int(msg[cur+1])
			// Requiring pointers to go strictly backwards means every jump
			// moves closer to the start of the message, so no loop can occur.
			switch {
			case target == cur:
				return "", off, ErrPointerLoop
			case target > cur:
				return "", off, ErrBadPointer
			}
			if next < 0 {
				next = cur + 2
			}
			cur = target

		default: // 0x40 and 0x80 are reserved
			return "", off, ErrBadLabelType
		}
	}
}
