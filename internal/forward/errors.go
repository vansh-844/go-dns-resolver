package forward

import "errors"

var (
	ErrNoUpstreams = errors.New("forward: no upstream resolvers configured")
	ErrBadUpstream = errors.New("forward: invalid upstream address")
	ErrNoAnswer    = errors.New("forward: no upstream answered")
)

// Reasons a datagram from an upstream is not accepted as the reply. They are
// only logged: the forwarder keeps waiting for the real reply.
var (
	errShortReply    = errors.New("forward: datagram shorter than a DNS header")
	errWrongID       = errors.New("forward: reply ID does not match the query")
	errNotResponse   = errors.New("forward: datagram is not a response")
	errWrongQuestion = errors.New("forward: reply question does not match the query")
)
