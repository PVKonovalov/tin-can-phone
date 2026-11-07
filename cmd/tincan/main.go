// Command tincan is the tin-can-phone server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
	"github.com/PVKonovalov/tin-can-phone/internal/httpserver"
	"github.com/PVKonovalov/tin-can-phone/internal/tlsmode"
	"github.com/PVKonovalov/tin-can-phone/web"
)

// version is set at build time: -ldflags "-X main.version=..."
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tincan: invalid configuration:\n%v\n", err)
		return 2
	}
	log.Info("tincan starting", append([]any{"version", version}, cfg.LogAttrs()...)...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode, err := tlsmode.Setup(ctx, cfg, log)
	if err != nil {
		log.Error("tls setup failed", "err", err)
		return 1
	}
	handler, err := httpserver.NewHandler(httpserver.Options{
		Version:    version,
		Static:     web.FS,
		HSTS:       mode.HSTS,
		InstallURL: mode.InstallURL,
	})
	if err != nil {
		log.Error("handler setup failed", "err", err)
		return 1
	}

	httpsLn, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		log.Error("listen https", "err", err)
		return 1
	}
	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		httpsLn.Close()
		log.Error("listen http", "err", err)
		return 1
	}

	err = httpserver.Run(ctx, log,
		httpserver.NewServer(handler, mode.TLSConfig, log), httpsLn,
		httpserver.NewServer(mode.HTTPHandler, nil, log), httpLn)
	if err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
