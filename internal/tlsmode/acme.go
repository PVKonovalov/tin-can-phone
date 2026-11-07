package tlsmode

import (
	"crypto/tls"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/acme/autocert"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
)

func setupACME(cfg *config.Config, httpsPort string, log *slog.Logger) (*tls.Config, http.Handler) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.ACMECacheDir),
		HostPolicy: autocert.HostWhitelist(cfg.ACMEDomains...),
		Email:      cfg.ACMEEmail,
	}
	if cfg.HTTPPort() != "80" {
		log.Warn("acme: HTTP-01 challenges arrive on port 80; make sure it is forwarded to HTTP_ADDR",
			"http_addr", cfg.HTTPAddr)
	}
	tc := m.TLSConfig() // includes the acme-tls/1 ALPN protocol for TLS-ALPN-01
	tc.MinVersion = tls.VersionTLS12
	return tc, m.HTTPHandler(RedirectHandler(httpsPort))
}
