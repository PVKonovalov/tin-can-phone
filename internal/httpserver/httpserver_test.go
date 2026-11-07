package httpserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
	"github.com/PVKonovalov/tin-can-phone/internal/httpserver"
	"github.com/PVKonovalov/tin-can-phone/internal/tlsmode"
	"github.com/PVKonovalov/tin-can-phone/web"
)

type running struct {
	httpsURL, httpURL string
	client            *http.Client
	cancel            context.CancelFunc
	done              chan error
}

// start runs the full server (as cmd/tincan wires it) on 127.0.0.1:0.
func start(t *testing.T, cfg *config.Config, roots *x509.CertPool) *running {
	t.Helper()
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HTTPSAddr, cfg.HTTPAddr = httpsLn.Addr().String(), httpLn.Addr().String()

	log := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	mode, err := tlsmode.Setup(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpserver.NewHandler(httpserver.Options{
		Version: "test-1.2.3", Static: web.FS, HSTS: mode.HSTS, InstallURL: mode.InstallURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- httpserver.Run(ctx, log,
			httpserver.NewServer(h, mode.TLSConfig, log), httpsLn,
			httpserver.NewServer(mode.HTTPHandler, nil, log), httpLn)
	}()

	if roots == nil {
		data, err := os.ReadFile(filepath.Join(cfg.SelfCADir, "ca.crt"))
		if err != nil {
			t.Fatal(err)
		}
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(data)
	}
	r := &running{
		httpsURL: "https://" + cfg.HTTPSAddr,
		httpURL:  "http://" + cfg.HTTPAddr,
		client: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cancel: cancel,
		done:   done,
	}
	t.Cleanup(func() { r.stop(t) })
	return r
}

func (r *running) stop(t *testing.T) {
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(httpserver.ShutdownTimeout + time.Second):
		t.Error("graceful shutdown timed out")
	}
}

func (r *running) get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := r.client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func selfCAConfig(t *testing.T) *config.Config {
	return &config.Config{TLSMode: config.ModeSelfCA, SelfCADir: filepath.Join(t.TempDir(), "ca")}
}

func TestHTTPSHealthz(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	resp, body := s.get(t, s.httpsURL+"/healthz")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if v["status"] != "ok" || v["version"] != "test-1.2.3" {
		t.Errorf("body %v", v)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("TLS state %+v", resp.TLS)
	}
}

func TestHTTPSIndexAndHeadersSelfCA(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	resp, body := s.get(t, s.httpsURL+"/")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "tin-can-phone") || !strings.Contains(body, "test-1.2.3") {
		t.Error("index content missing")
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.httpURL, "http://"))
	if want := `href="http://127.0.0.1:` + port + `/install"`; !strings.Contains(body, want) {
		t.Errorf("index lacks install link %s:\n%s", want, body)
	}
	for _, bad := range []string{"{{", "http://cdn", "https://", "<script src=\"http"} {
		if strings.Contains(body, bad) {
			t.Errorf("index contains %q", bad)
		}
	}
	wantHeaders := map[string]string{
		"Content-Security-Policy": httpserver.ContentSecurityPolicy,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "microphone=(self)",
	}
	for k, v := range wantHeaders {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if !strings.Contains(httpserver.ContentSecurityPolicy, "default-src 'self'") {
		t.Error("CSP lacks default-src 'self'")
	}
	if h := resp.Header.Get("Strict-Transport-Security"); h != "" {
		t.Errorf("HSTS must not be sent in selfca mode, got %q", h)
	}

	resp, body = s.get(t, s.httpsURL+"/style.css")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") {
		t.Errorf("style.css: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if strings.Contains(body, "@import") || strings.Contains(body, "url(http") {
		t.Error("style.css references external resources")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("security headers missing on static files")
	}

	resp, _ = s.get(t, s.httpsURL+"/index.html")
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("/index.html: %d", resp.StatusCode)
	}
	resp, _ = s.get(t, s.httpsURL+"/nope")
	if resp.StatusCode != 404 {
		t.Errorf("/nope: %d", resp.StatusCode)
	}
	resp, _ = s.get(t, s.httpsURL+"/embed.go")
	if resp.StatusCode != 404 {
		t.Errorf("/embed.go: %d", resp.StatusCode)
	}
}

func TestPlainHTTPListenerSelfCA(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	resp, body := s.get(t, s.httpURL+"/install")
	if resp.StatusCode != 200 || !strings.Contains(body, "SHA-256") {
		t.Errorf("/install: %d", resp.StatusCode)
	}
	resp, _ = s.get(t, s.httpURL+"/healthz?a=b")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != s.httpsURL+"/healthz?a=b" {
		t.Errorf("Location %q, want %q", loc, s.httpsURL+"/healthz?a=b")
	}
}

func TestFilesModeHSTS(t *testing.T) {
	// Mint a CA + server cert with selfca, then serve them in files mode.
	caDir := filepath.Join(t.TempDir(), "ca")
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := tlsmode.Setup(ctx, &config.Config{TLSMode: config.ModeSelfCA, SelfCADir: caDir}, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	cancel()
	data, _ := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(data)

	s := start(t, &config.Config{
		TLSMode: config.ModeFiles,
		TLSCert: filepath.Join(caDir, "server.crt"),
		TLSKey:  filepath.Join(caDir, "server.key"),
	}, roots)
	resp, body := s.get(t, s.httpsURL+"/")
	if h := resp.Header.Get("Strict-Transport-Security"); !strings.HasPrefix(h, "max-age=") {
		t.Errorf("HSTS %q", h)
	}
	if strings.Contains(body, "/install") {
		t.Error("install link shown outside selfca mode")
	}
	resp, _ = s.get(t, s.httpURL+"/install")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("files mode /install should redirect, got %d", resp.StatusCode)
	}
}

func TestTLS11Rejected(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	conn, err := tls.Dial("tcp", strings.TrimPrefix(s.httpsURL, "https://"), &tls.Config{
		InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11,
	})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded")
	}
}

func TestGracefulShutdown(t *testing.T) {
	s := start(t, selfCAConfig(t), nil)
	s.get(t, s.httpsURL+"/healthz")
	s.stop(t)
	if _, err := s.client.Get(s.httpsURL + "/healthz"); err == nil {
		t.Error("server still answering after shutdown")
	}
}
