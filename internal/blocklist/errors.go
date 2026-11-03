package blocklist

import "errors"

var (
	ErrNilHandler = errors.New("blocklist: nil handler")
	ErrNilList    = errors.New("blocklist: nil list")
	ErrBadMode    = errors.New("blocklist: unknown mode, want null or nxdomain")
)
