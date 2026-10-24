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
		upstreams := strings.Split(*upstream, ",")
		for i := range upstreams {
			upstreams[i] = strings.TrimSpace(upstreams[i])
		}
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
	} else {
		static, err := staticHandler(*ip, *ttl)
		if err != nil {
			return err
		}
		logger.Info("answering with a fixed address", "ip", *ip, "ttl", *ttl)
		handler = static
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
