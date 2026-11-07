// Command tincan is the tin-can-phone server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	ossignal "os/signal"
	"syscall"

	"github.com/PVKonovalov/tin-can-phone/internal/api"
	"github.com/PVKonovalov/tin-can-phone/internal/config"
	"github.com/PVKonovalov/tin-can-phone/internal/httpserver"
	"github.com/PVKonovalov/tin-can-phone/internal/room"
	"github.com/PVKonovalov/tin-can-phone/internal/signal"
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

	ctx, stop := ossignal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode, err := tlsmode.Setup(ctx, cfg, log)
	if err != nil {
		log.Error("tls setup failed", "err", err)
		return 1
	}
	rooms := room.NewManager(room.Options{MaxPeers: cfg.MaxPeers, MaxRooms: cfg.MaxRooms, TTL: cfg.RoomTTL})
	go rooms.Run(ctx)
	sig := signal.New(signal.Options{
		Rooms:          rooms,
		Media:          room.NewUnavailableMedia(), // replaced by the SFU in step 3
		AllowedOrigins: cfg.AllowedOrigins,
		Log:            log,
	})
	handler, err := httpserver.NewHandler(httpserver.Options{
		Version:    version,
		Static:     web.FS,
		HSTS:       mode.HSTS,
		InstallURL: mode.InstallURL,
		API:        api.New(api.Options{Rooms: rooms, PublicURL: cfg.PublicURL, Log: log}),
		WS:         sig,
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
		httpserver.NewServer(mode.HTTPHandler, nil, log), httpLn,
		sig.Shutdown)
	if err != nil {
		return 1
	}
	log.Info("stopped")
	return 0
}
