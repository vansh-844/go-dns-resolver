# AGENTS.md

Guidance for AI coding agents working in this repository.

## Overview

`pidns` is a small DNS resolver written in Go, built to run on a Raspberry Pi. It listens on UDP, optionally blocks ad/tracking domains, caches answers, and forwards everything else to upstream resolvers (default `1.1.1.1` / `1.0.0.1`).

- Module: `github.com/vansh-844/pidns` (the repo directory and binary are named `dns-resolver`)
- Go 1.25.1, **standard library only** (no third-party dependencies). Do not add any without asking.
- The DNS wire format is implemented from scratch in `internal/dnsmessage`; do not swap in `golang.org/x/net/dns/dnsmessage` or `miekg/dns`.
- UDP only. Responses over 512 bytes (`maxUDPSize`) are replaced with an empty TC=1 reply. There is no TCP listener and no DNSSEC.

## Layout

```
cmd/resolverd/       main binary: flag parsing, handler wiring, signals, shutdown
cmd/capture/         dev tool: sends a query to a real server, saves the reply as hex for fixtures
internal/dnsmessage/ DNS wire format: Message, Header, Question, ResourceRecord, rdata types, name compression
internal/server/     UDP server (sockets, concurrency, shutdown) + the Handler interface + StaticHandler
internal/forward/    Forwarder: sends a query to upstreams in order, validates the reply
internal/cache/      Cache: LRU answer cache with TTL handling and negative caching
internal/blocklist/  List (hosts/domain/adblock parser) and Blocker (handler that short-circuits blocked names)
blocklists/          downloaded lists, gitignored (`make blocklist`)
build/, build-pi/    build output, gitignored
```

## Architecture

Everything that answers queries is a `server.Handler`:

```go
Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error)
```

Handlers are decorators, composed in `cmd/resolverd/main.go`:

```
server.Server  ->  Blocker  ->  Cache  ->  Forwarder  ->  upstreams
                   (optional)   (optional)
```

or, with `-upstream=""`, `Blocker -> StaticHandler` (answers every A query with a fixed IP).

Key rules:

- **The server fills in nothing for the handler.** A response must carry the query's ID and questions and have QR set. Use `dnsmessage.NewResponse(query, rcode)` to build one.
- A handler error becomes SERVFAIL; unparseable packets get FORMERR; packets that are too short or already responses are dropped.
- Handlers are called from many goroutines at once, so they must be safe for concurrent use. `blocklist.List` is immutable after construction, and `Blocker` swaps it atomically (`SetList`) for SIGHUP reloads.
- **Packages do not import each other's handler types.** `cache` and `blocklist` each declare their own small `Handler` interface instead of importing `server`, so `server` stays free of dependents. Keep it that way: `internal/dnsmessage` imports nothing internal, and `internal/server` imports only `dnsmessage`.
- The blocker sits in front of the cache so a blocked name never reaches the cache or an upstream. Preserve that ordering.
- Pass `ctx` to anything that blocks. It is cancelled on shutdown or request timeout.

## Commands

```sh
make check        # fmt-check + vet + test (run before finishing any change)
make test         # go test -race ./...
make vet          # go vet ./...
make fmt          # gofmt -w .
make build        # build/dns-resolver
make run          # go run ./cmd/resolverd
make build-pi     # cross-compile for linux/arm64 (PI_GOARCH=arm GOARM=7 for 32-bit)
make deploy       # scp to the Pi (PI_HOST / PI_PATH overridable) - touches a remote machine, don't run unprompted
make blocklist    # download StevenBlack hosts into blocklists/stevenblack.txt (BLOCKLIST_URL overridable)
make capture      # regenerate fixtures from a live resolver - needs network
```

Run a single test: `go test -race -run TestName ./internal/cache/`.

Try it locally (port 8080 by default, so no root needed):

```sh
go run ./cmd/resolverd -listen :8053 -log-level debug
dig @127.0.0.1 -p 8053 example.com
```

`resolverd` flags: `-listen`, `-upstream`, `-upstream-timeout`, `-cache-size` (0 disables), `-cache-max-ttl`, `-blocklist` (comma-separated files, reloaded on SIGHUP), `-block-mode` (`null` or `nxdomain`), `-ip`, `-ttl`, `-log-level`. When you add a flag, update this list.

## Conventions

Match the existing code; it is consistent.

- **Comments**: every package has a doc comment, and every exported identifier has a doc comment written as prose that explains behavior and why, not a restatement of the name. Constants explain their purpose. Keep the same density as surrounding code.
- **Errors**: sentinel errors live in a per-package `errors.go`, prefixed with the package name (`errors.New("cache: nil handler")`). Wrap with `%w`; callers use `errors.Is`/`errors.As`. `dnsmessage` returns `*ParseError` (section + offset) wrapping a sentinel. Errors that are only logged (e.g. `forward`'s reply-rejection reasons) are unexported.
- **Config structs**: each component takes a `Config` with a zero-value-means-default rule, implemented by unexported accessor methods (`cfg.maxEntries()`, `cfg.timeout()`). Document the default on the field. Constructors validate and return an error (e.g. `ErrNilHandler`).
- **Logging**: `log/slog`. Components take an optional `Logger` in their config and fall back to `slog.Default()` through a `log()` helper. Use structured key/value pairs, with `Debug` for per-query detail, `Warn` for bad input, `Error` for failures.
- **Naming**: standard Go style; DNS terms follow the RFCs (`RCodeFormatError`, `TypeAAAA`). Unpacked names are plain strings without a trailing dot (the root is `""`); packing accepts an optional trailing dot. Check `internal/dnsmessage/name.go` before adding name handling, and note that DNS names are case-insensitive, so normalize when comparing or keying.
- **Safety bounds**: input parsing guards against hostile data (compression pointer loops, allocation sized by header counts, label/name length limits). Keep new parsing code defensive and bounded.
- **Formatting**: `gofmt` clean (`make fmt-check` is part of `make check`).

## Testing

- Tests sit next to the code (`*_test.go`), one test file per source file, and run with `-race`.
- Handlers are tested without a network by calling `Handle` directly. Use `server.HandlerFunc` or small fakes for the next handler.
- `internal/server` and `internal/forward` tests use real loopback UDP sockets on `127.0.0.1` with port 0 (never fixed ports).
- Helpers call `t.Helper()` and fail with `t.Fatal`/`t.Fatalf`. Test helpers live in the `_test.go` files (e.g. `packet_test.go`).
- Real wire captures live in `internal/dnsmessage/testdata/*.hex` (hex, wrapped at 32 bytes per line). Regenerate or add them with `cmd/capture` (see the `capture` Make target).
- Add or update tests with every behavior change. Bug fixes get a regression test.

## Things to avoid

- Don't run `make deploy` or `make capture`, or any command that contacts the Pi or the network, unless asked.
- Don't commit `build/`, `build-pi/`, or `blocklists/` (all gitignored).
- Don't change the handler contract (`server.Handler`) without updating every implementer: `Forwarder`, `Cache`, `Blocker`, `StaticHandler`.
- Don't add TCP, DoH/DoT, or DNSSEC as a side effect of an unrelated change; they are out of scope for now.
