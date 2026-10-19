package dnsmessage

import (
	"errors"
	"fmt"
)

var (
	ErrShortBuffer  = errors.New("dnsmsg: message too short")
	ErrPointerLoop  = errors.New("dnsmsg: compression pointer loop")
	ErrBadPointer   = errors.New("dnsmsg: compression pointer does not point backwards")
	ErrBadLabelType = errors.New("dnsmsg: reserved label type")
	ErrLabelTooLong = errors.New("dnsmsg: label exceeds 63 bytes")
	ErrEmptyLabel   = errors.New("dnsmsg: empty label in name")
	ErrNameTooLong  = errors.New("dnsmsg: name exceeds 255 bytes")
	ErrBadRDLength  = errors.New("dnsmsg: RDATA length does not match record")
	ErrBadAddr      = errors.New("dnsmsg: address has wrong family for record type")
	ErrTooMany      = errors.New("dnsmsg: too many records or RDATA too large")

	ErrTXTStringTooLong = errors.New("dnsmsg: TXT string exceeds 255 bytes")
	ErrNoData           = errors.New("dnsmsg: resource record has no data")
	ErrNilMessage       = errors.New("dnsmsg: cannot pack a nil message")
)

type ParseError struct {
	Section string
	Offset  int
	Err     error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("dnsmsg: %s at offset %d: %v", e.Section, e.Offset, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}
