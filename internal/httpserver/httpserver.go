// Package httpserver builds the HTTPS handler and runs the HTTPS and
// plain-HTTP listeners with graceful shutdown.
package httpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/room"
)

// Timeouts shared by both listeners.
const (
	ReadHeaderTimeout = 10 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 64 << 10
	ShutdownTimeout   = 10 * time.Second
)

// ContentSecurityPolicy allows only same-origin resources. connect-src is
// extended per request with wss://<host> (see SecurityHeaders): CSP3 browsers
// already match same-origin wss: with 'self', older Safari versions do not.
const ContentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; " +
	"frame-ancestors 'none'; form-action 'self'; connect-src 'self'"

// validHost matches a Host header safe to embed in the CSP.
var validHost = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

// Options configures the HTTPS handler.
type Options struct {
	Version string
	// Static holds index.html (an html/template) and other client files.
	Static fs.FS
	// HSTS enables Strict-Transport-Security.
	HSTS bool
	// InstallURL, if set, returns the CA install page URL shown on the index page.
	InstallURL func(r *http.Request) string
	// API serves /api/ (optional).
	API http.Handler
	// WS serves /ws (optional).
	WS http.Handler
}

// NewHandler returns the HTTPS handler: index page, static files and /healthz,
// wrapped with security headers.
func NewHandler(opts Options) (http.Handler, error) {
	index, err := template.ParseFS(opts.Static, "index.html")
	if err != nil {
		return nil, fmt.Errorf("httpserver: parse index.html: %w", err)
	}
	health, _ := json.Marshal(map[string]string{"status": "ok", "version": opts.Version})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(health)
	})
	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{"Version": opts.Version}
		if opts.InstallURL != nil {
			data["InstallURL"] = opts.InstallURL(r)
		}
		var buf bytes.Buffer
		if err := index.Execute(&buf, data); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(buf.Bytes())
	}
	mux.HandleFunc("GET /{$}", serveIndex)
	// The UI decides what to show for a room; it calls GET /api/rooms/{id}.
	mux.HandleFunc("GET /room/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !room.ValidID(r.PathValue("id")) {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r)
	})
	if opts.API != nil {
		mux.Handle("/api/", opts.API)
	}
	if opts.WS != nil {
		mux.Handle("GET /ws", opts.WS)
	}
	files := http.FileServerFS(opts.Static)
	// Registered without a method so it does not conflict with "/api/".
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/index.html" { // the raw template is never served
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	return SecurityHeaders(mux, opts.HSTS), nil
}

// SecurityHeaders adds the standard security headers to every response.
func SecurityHeaders(next http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		csp := ContentSecurityPolicy
		if validHost.MatchString(r.Host) {
			csp += " wss://" + r.Host
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "microphone=(self)")
		next.ServeHTTP(w, r)
	})
}

// NewServer returns an http.Server with sensible timeouts. tlsConfig may be
// nil for the plain-HTTP listener.
func NewServer(h http.Handler, tlsConfig *tls.Config, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		// TLS handshake failures (e.g. clients that do not trust the selfca CA yet)
		// are routine; keep them at debug level.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
}

// Run serves HTTPS on httpsLn and plain HTTP on httpLn until ctx is done or
// one of the servers fails, then shuts both down gracefully. beforeShutdown
// hooks (e.g. closing WebSockets, which http.Server.Shutdown does not track)
// run first, sharing the shutdown timeout.
func Run(ctx context.Context, log *slog.Logger, httpsSrv *http.Server, httpsLn net.Listener, httpSrv *http.Server, httpLn net.Listener, beforeShutdown ...func(context.Context) error) error {
	errc := make(chan error, 2)
	go func() { errc <- fmt.Errorf("https: %w", httpsSrv.ServeTLS(httpsLn, "", "")) }()
	go func() { errc <- fmt.Errorf("http: %w", httpSrv.Serve(httpLn)) }()
	log.Info("listening", "https", httpsLn.Addr().String(), "http", httpLn.Addr().String())

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errc:
		log.Error("server failed", "err", runErr)
	}

	sctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	var hookErrs []error
	for _, hook := range beforeShutdown {
		hookErrs = append(hookErrs, hook(sctx))
	}
	shutdownErr := errors.Join(append(hookErrs, httpsSrv.Shutdown(sctx), httpSrv.Shutdown(sctx))...)
	if shutdownErr != nil {
		log.Error("shutdown", "err", shutdownErr)
	}
	return errors.Join(runErr, shutdownErr)
}
