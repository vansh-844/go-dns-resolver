package server

import (
	"context"
	"errors"
	"testing"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

var _ Handler = HandlerFunc(nil)

func TestHandlerFunc(t *testing.T) {
	wantErr := errors.New("boom")
	query := &dnsmessage.Message{Header: dnsmessage.Header{ID: 42}}

	var h Handler = HandlerFunc(func(ctx context.Context, q *dnsmessage.Message) (*dnsmessage.Message, error) {
		if q != query {
			t.Errorf("handler got %p, want the query passed to Handle (%p)", q, query)
		}
		return &dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID}}, wantErr
	})

	resp, err := h.Handle(context.Background(), query)
	if resp == nil || resp.Header.ID != 42 {
		t.Errorf("response = %+v, want ID 42", resp)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}
