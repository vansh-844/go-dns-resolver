// Package server serves DNS over the network. It owns sockets, concurrency and
// shutdown, and knows nothing about how a query is answered: that is the job
// of a Handler, which can be tested without any networking.
package server

import (
	"context"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

// A Handler answers DNS queries.
//
// Handle receives a parsed query and returns the response to send back. The
// server fills in nothing on the handler's behalf, so the response must carry
// the query's ID and questions, have the QR bit set, and so on.
//
// If Handle returns an error, the server replies to the client with SERVFAIL
// and logs the error. The response must be non-nil when the error is nil.
//
// ctx is cancelled when the server shuts down or the request times out, and
// should be passed to anything that blocks, such as an upstream lookup.
//
// Handle may be called from many goroutines at once.
type Handler interface {
	Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error)
}

// HandlerFunc lets an ordinary function be used as a Handler.
type HandlerFunc func(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error)

// Handle calls f(ctx, query).
func (f HandlerFunc) Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	return f(ctx, query)
}
