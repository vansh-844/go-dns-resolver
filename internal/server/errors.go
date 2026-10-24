package server

import "errors"

var (
	ErrNotIPv4       = errors.New("server: address is not an IPv4 address")
	ErrServerClosed  = errors.New("server: server closed")
	ErrServerStarted = errors.New("server: server already started")
	ErrNilHandler    = errors.New("server: nil handler")
	ErrNotListening  = errors.New("server: not listening, call Listen first")
)
