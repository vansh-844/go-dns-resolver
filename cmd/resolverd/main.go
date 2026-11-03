// Command resolverd is a DNS server. It forwards queries to upstream
// resolvers, or, with -upstream="", answers every A query with one fixed
// address.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vansh-844/pidns/internal/blocklist"
	"github.com/vansh-844/pidns/internal/cache"
	"github.com/vansh-844/pidns/internal/forward"
	"github.com/vansh-844/pidns/internal/server"
)

const shutdownTimeout = 5 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "resolverd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen          = flag.String("listen", ":8080", "address to listen on, as host:port")
		upstream        = flag.String("upstream", "1.1.1.1:53,1.0.0.1:53", `comma-separated upstream resolvers, as host:port, tried in order; "" answers with -ip instead`)
		upstreamTimeout = flag.Duration("upstream-timeout", time.Second, "how long to wait for each upstream")
		cacheSize       = flag.Int("cache-size", 10_000, "number of answers to cache; 0 disables the cache")
		cacheMaxTTL     = flag.Duration("cache-max-ttl", 24*time.Hour, "longest time an answer is cached")
		blocklists      = flag.String("blocklist", "", "comma-separated blocklist files (hosts, domain or adblock format); empty disables blocking; reloaded on SIGHUP")
		blockMode       = flag.String("block-mode", "null", "answer for blocked names: null (0.0.0.0 and ::) or nxdomain")
		ip              = flag.String("ip", "127.0.0.1", `IPv4 address returned for every A query, when -upstream is ""`)
		ttl             = flag.Uint("ttl", 60, `TTL in seconds of the returned records, when -upstream is ""`)
		logLevel        = flag.String("log-level", "info", "log level: debug, info, warn or error")
	)
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q: %w", *logLevel, err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	var handler server.Handler
	if *upstream != "" {
		upstreams := splitList(*upstream)
		fwd, err := forward.New(forward.Config{
			Upstreams: upstreams,
			Timeout:   *upstreamTimeout,
			Logger:    logger,
		})
		if err != nil {
			return fmt.Errorf("invalid -upstream %q: %w", *upstream, err)
		}
		logger.Info("forwarding queries", "upstreams", upstreams, "timeout", *upstreamTimeout)
		handler = fwd

		if *cacheSize > 0 {
			c, err := cache.New(fwd, cache.Config{MaxEntries: *cacheSize, MaxTTL: *cacheMaxTTL})
			if err != nil {
				return err
			}
			logger.Info("caching answers", "max_entries", *cacheSize, "max_ttl", *cacheMaxTTL)
			handler = c
		}
	} else {
		static, err := staticHandler(*ip, *ttl)
		if err != nil {
			return err
		}
		logger.Info("answering with a fixed address", "ip", *ip, "ttl", *ttl)
		handler = static
	}

	// The blocker goes in front of everything else, so that a blocked name
	// never reaches the cache or an upstream.
	var (
		blocker    *blocklist.Blocker
		blockPaths = splitList(*blocklists)
	)
	if len(blockPaths) > 0 {
		mode, err := blocklist.ParseMode(*blockMode)
		if err != nil {
			return fmt.Errorf("invalid -block-mode: %w", err)
		}
		list, err := loadBlocklist(logger, blockPaths)
		if err != nil {
			return fmt.Errorf("invalid -blocklist: %w", err)
		}
		blocker, err = blocklist.New(handler, list, blocklist.Config{Mode: mode, Logger: logger})
		if err != nil {
			return err
		}
		handler = blocker
	}

	srv, err := server.NewServer(server.ServerConfig{
		Addr:    *listen,
		Handler: handler,
		Logger:  logger,
	})
	if err != nil {
		return err
	}
	// Bind before anything else, so that a bad or busy address fails right away.
	if err := srv.Listen(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if blocker != nil {
		go reloadOnHangup(ctx, logger, blocker, blockPaths)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	select {
	case err := <-serveErr:
		return err // the server stopped by itself
	case <-ctx.Done():
	}
	stop() // a second Ctrl-C now kills the process instead of waiting
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return <-serveErr
}

// splitList splits a comma-separated flag value, trimming spaces and dropping
// empty items.
func splitList(s string) []string {
	var out []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// loadBlocklist loads the blocklist files and logs what was loaded.
func loadBlocklist(logger *slog.Logger, paths []string) (*blocklist.List, error) {
	start := time.Now()
	list, skipped, err := blocklist.Load(paths...)
	if err != nil {
		return nil, err
	}
	logger.Info("blocklist loaded", "domains", list.Len(), "skipped_lines", skipped,
		"files", paths, "took", time.Since(start).Round(time.Millisecond))
	return list, nil
}

// reloadOnHangup reloads the blocklist each time the process receives
// SIGHUP (kill -HUP <pid>), until ctx is cancelled. If loading fails, the
// old list stays in use.
func reloadOnHangup(ctx context.Context, logger *slog.Logger, blocker *blocklist.Blocker, paths []string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			list, err := loadBlocklist(logger, paths)
			if err != nil {
				logger.Error("reloading blocklist failed, keeping the old one", "err", err)
				continue
			}
			blocker.SetList(list) // list is not nil, so this cannot fail
		}
	}
}

// staticHandler builds the handler used when there are no upstreams.
func staticHandler(ip string, ttl uint) (*server.StaticHandler, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid -ip %q: %w", ip, err)
	}
	if ttl > math.MaxUint32 {
		return nil, fmt.Errorf("invalid -ttl %d: must fit in 32 bits", ttl)
	}
	h, err := server.NewStaticHandler(addr, uint32(ttl))
	if err != nil {
		return nil, fmt.Errorf("invalid -ip %q: %w", ip, err)
	}
	return h, nil
}
