package dnsmessage

import "encoding/binary"

// resourceHeaderSize is the size of the fixed fields that follow a record's
// name: TYPE (2), CLASS (2), TTL (4) and RDLENGTH (2).
const resourceHeaderSize = 10

// maxRDataLen is the largest RDATA that fits in the 16-bit RDLENGTH field.
const maxRDataLen = 0xFFFF

// ResourceRecord is an entry in the answer, authority or additional section
// of a message (RFC 1035 §4.1.3). Its type is determined by Data.
type ResourceRecord struct {
	Name  string
	Class Class
	TTL   uint32
	Data  ResourceData
}

// Type returns the record type, or 0 if the record has no data.
func (r ResourceRecord) Type() Type {
	if r.Data == nil {
		return 0
	}
	return r.Data.Type()
}

// unpackResourceRecord decodes the record starting at msg[off]. msg must be
// the whole message. It returns the record and the offset just past it.
func unpackResourceRecord(msg []byte, off int) (ResourceRecord, int, error) {
	name, next, err := unpackName(msg, off)
	if err != nil {
		return ResourceRecord{}, off, err
	}
	if next+resourceHeaderSize > len(msg) {
		return ResourceRecord{}, off, ErrShortBuffer
	}

	t := Type(binary.BigEndian.Uint16(msg[next : next+2]))
	class := Class(binary.BigEndian.Uint16(msg[next+2 : next+4]))
	ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
	rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))

	start := next + resourceHeaderSize
	end := start + rdLen
	if end > len(msg) {
		return ResourceRecord{}, off, ErrShortBuffer
	}

	data, err := unpackRData(msg, start, end, t)
	if err != nil {
		return ResourceRecord{}, off, err
	}
	return ResourceRecord{Name: name, Class: class, TTL: ttl, Data: data}, end, nil
}

// appendTo appends the uncompressed wire encoding of r to b and returns the
// extended slice. On error it returns nil.
func (r ResourceRecord) appendTo(b []byte) ([]byte, error) {
	if r.Data == nil {
		return nil, ErrNoData
	}
	b, err := appendName(b, r.Name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(r.Data.Type()))
	b = binary.BigEndian.AppendUint16(b, uint16(r.Class))
	b = binary.BigEndian.AppendUint32(b, r.TTL)

	// RDLENGTH is only known after the data is written, so reserve space for
	// it and fill it in afterwards.
	lenOff := len(b)
	b = append(b, 0, 0)
	b, err = r.Data.appendTo(b)
	if err != nil {
		return nil, err
	}
	rdLen := len(b) - lenOff - 2
	if rdLen > maxRDataLen {
		return nil, ErrTooMany
	}
	binary.BigEndian.PutUint16(b[lenOff:], uint16(rdLen))
	return b, nil
}
