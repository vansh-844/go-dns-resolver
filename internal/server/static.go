package server

import (
	"context"
	"net/netip"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

// StaticHandler answers every A query with the same IPv4 address. It exists to
// exercise the server end to end before a real resolver is plugged in.
//
// Responses by query:
//   - one A question in class IN: NOERROR with a single A record
//   - one question of any other type in class IN: NOERROR with no answers
//   - a class other than IN: REFUSED
//   - an opcode other than a standard query: NOTIMP
//   - zero or several questions: FORMERR
type StaticHandler struct {
	addr netip.Addr
	ttl  uint32
}

// NewStaticHandler returns a handler that answers A queries with addr and the
// given TTL in seconds. It returns ErrNotIPv4 if addr is not an IPv4 address.
func NewStaticHandler(addr netip.Addr, ttl uint32) (*StaticHandler, error) {
	if !addr.Is4() {
		return nil, ErrNotIPv4
	}
	return &StaticHandler{addr: addr, ttl: ttl}, nil
}

// Handle implements Handler.
func (h *StaticHandler) Handle(_ context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	switch {
	case len(query.Questions) != 1:
		return dnsmessage.NewResponse(query, dnsmessage.RCodeFormatError), nil
	case query.Header.Opcode() != dnsmessage.OpcodeQuery:
		return dnsmessage.NewResponse(query, dnsmessage.RCodeNotImplemented), nil
	}

	q := query.Questions[0]
	if q.Class != dnsmessage.ClassIN {
		return dnsmessage.NewResponse(query, dnsmessage.RCodeRefused), nil
	}

	resp := dnsmessage.NewResponse(query, dnsmessage.RCodeSuccess)
	if q.Type == dnsmessage.TypeA {
		resp.Answers = []dnsmessage.ResourceRecord{{
			Name:  q.Name, // echoed as received, which keeps its letter case
			Class: dnsmessage.ClassIN,
			TTL:   h.ttl,
			Data:  dnsmessage.A{Addr: h.addr},
		}}
	}
	return resp, nil
}
