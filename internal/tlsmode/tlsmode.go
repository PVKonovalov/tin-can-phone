// Package tlsmode provides the HTTPS TLS configuration and the plain-HTTP
// (port 80) handler for each TLS mode: acme, files and selfca.
package tlsmode

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
)

// Mode is the result of setting up a TLS mode.
type Mode struct {
	// TLSConfig is used by the HTTPS listener. MinVersion is TLS 1.2.
	TLSConfig *tls.Config
	// HTTPHandler serves the plain-HTTP listener (port 80).
	HTTPHandler http.Handler
	// HSTS reports whether the HTTPS server should send Strict-Transport-Security.
	// It is false in selfca mode, where users may need to fall back to the
	// plain-HTTP install page.
	HSTS bool
	// InstallURL, when non-nil (selfca mode), returns the plain-HTTP URL of the
	// CA install page for the host the request was made to.
	InstallURL func(r *http.Request) string
}

// Setup prepares the TLS mode selected in cfg. Background work (SIGHUP
// reloading in files mode, server certificate renewal in selfca mode) stops
// when ctx is done.
func Setup(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Mode, error) {
	httpsPort, httpPort := cfg.HTTPSPort(), cfg.HTTPPort()
	switch cfg.TLSMode {
	case config.ModeFiles:
		r, err := newFileReloader(cfg.TLSCert, cfg.TLSKey, log)
		if err != nil {
			return nil, err
		}
		go r.watchSIGHUP(ctx)
		tc := baseTLSConfig()
		tc.GetCertificate = r.GetCertificate
		return &Mode{TLSConfig: tc, HTTPHandler: RedirectHandler(httpsPort), HSTS: true}, nil

	case config.ModeACME:
		tc, h := setupACME(cfg, httpsPort, log)
		return &Mode{TLSConfig: tc, HTTPHandler: h, HSTS: true}, nil

	case config.ModeSelfCA:
		hostname, _ := os.Hostname()
		ca, err := openSelfCA(selfCAOptions{
			Dir:      cfg.SelfCADir,
			SANs:     cfg.SelfCASANs,
			Hostname: hostname,
			Log:      log,
		})
		if err != nil {
			return nil, err
		}
		go ca.maintain(ctx)
		log.Info("selfca: CA ready",
			"subject", ca.caCert.Subject.CommonName,
			"sha256", ca.Fingerprint(),
			"not_after", ca.caCert.NotAfter)
		tc := baseTLSConfig()
		tc.GetCertificate = ca.GetCertificate
		return &Mode{
			TLSConfig:   tc,
			HTTPHandler: newInstallHandler(ca, httpsPort, httpPort),
			HSTS:        false,
			InstallURL:  func(r *http.Request) string { return InstallURL(r.Host, httpPort) },
		}, nil
	}
	return nil, fmt.Errorf("tlsmode: unknown mode %q", cfg.TLSMode)
}

func baseTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// RedirectHandler redirects every request to the same host and path over
// HTTPS (308, so the method and body are preserved).
func RedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, ok := httpsURL(r, httpsPort)
		if !ok {
			http.Error(w, "missing Host header", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func httpsURL(r *http.Request, httpsPort string) (string, bool) {
	host := hostOnly(r.Host)
	if host == "" {
		return "", false
	}
	u := url.URL{
		Scheme:   "https",
		Host:     withPort(host, httpsPort, "443"),
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	return u.String(), true
}

// InstallURL returns the plain-HTTP install page URL for requestHost.
func InstallURL(requestHost, httpPort string) string {
	u := url.URL{Scheme: "http", Host: withPort(hostOnly(requestHost), httpPort, "80"), Path: "/install"}
	return u.String()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	// No port; strip IPv6 brackets if present.
	if len(hostport) > 1 && hostport[0] == '[' && hostport[len(hostport)-1] == ']' {
		return hostport[1 : len(hostport)-1]
	}
	return hostport
}

func withPort(host, port, defaultPort string) string {
	if port == "" || port == defaultPort {
		if net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}
