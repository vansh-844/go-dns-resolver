package server

import "errors"

var ErrNotIPv4 = errors.New("server: address is not an IPv4 address")
