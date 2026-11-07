package tlsmode

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// fileReloader serves a certificate loaded from disk and reloads it on SIGHUP.
type fileReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	cert              atomic.Pointer[tls.Certificate]
}

func newFileReloader(certFile, keyFile string, log *slog.Logger) (*fileReloader, error) {
	r := &fileReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads the certificate and key again. On failure the previous
// certificate stays in use.
func (r *fileReloader) Reload() error {
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("files: load %s / %s: %w", r.certFile, r.keyFile, err)
	}
	r.cert.Store(&c)
	r.log.Info("files: certificate loaded",
		"subject", c.Leaf.Subject.CommonName, "dns", c.Leaf.DNSNames, "not_after", c.Leaf.NotAfter)
	return nil
}

func (r *fileReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

func (r *fileReloader) watchSIGHUP(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := r.Reload(); err != nil {
				r.log.Error("files: reload failed, keeping previous certificate", "err", err)
			}
		}
	}
}
