package tlsmode

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallHandlerCACert(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), nil, time.Now())
	h := newInstallHandler(ca, "8443", "8080")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://tincan.lan:8080/ca.crt", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Errorf("content type %q", ct)
	}
	b, _ := pem.Decode(rec.Body.Bytes())
	if b == nil {
		t.Fatal("not PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Raw, ca.CACertDER()) || !c.IsCA {
		t.Error("served certificate is not the CA")
	}
}

func TestInstallHandlerMobileConfig(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), nil, time.Now())
	h := newInstallHandler(ca, "443", "80")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://tincan.lan/ca.mobileconfig", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config" {
		t.Errorf("content type %q", ct)
	}

	// Walk the plist and collect <key>/<value> pairs plus the <data> payload.
	dec := xml.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.Strict = true
	var (
		lastKey, elem string
		payloadTypes  []string
		data          []byte
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid XML: %v", err)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			elem = v.Name.Local
		case xml.CharData:
			s := strings.TrimSpace(string(v))
			switch elem {
			case "key":
				lastKey = s
			case "string":
				if lastKey == "PayloadType" {
					payloadTypes = append(payloadTypes, s)
				}
			case "data":
				if lastKey == "PayloadContent" {
					if data, err = base64.StdEncoding.DecodeString(s); err != nil {
						t.Fatalf("bad base64: %v", err)
					}
				}
			}
		case xml.EndElement:
			elem = ""
		}
	}
	if strings.Join(payloadTypes, ",") != "com.apple.security.root,Configuration" {
		t.Errorf("payload types %v", payloadTypes)
	}
	if !bytes.Equal(data, ca.CACertDER()) {
		t.Error("profile payload is not the CA certificate (DER)")
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		t.Error(err)
	}

	// Stable across restarts (same CA → same profile).
	if !bytes.Equal(mobileConfig(ca), rec.Body.Bytes()) {
		t.Error("profile not deterministic")
	}
}

func TestInstallHandlerPage(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), nil, time.Now())
	h := newInstallHandler(ca, "8443", "8080")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://192.168.1.10:8080/install", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "style-src 'sha256-") {
		t.Errorf("CSP %q", csp)
	}
	body := rec.Body.String()
	for _, want := range []string{
		ca.Fingerprint(), "Android", "iPhone", "Windows", "macOS", "Linux",
		`href="/ca.crt"`, `href="/ca.mobileconfig"`, "https://192.168.1.10:8443/",
		"Certificate Trust Settings",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("install page lacks %q", want)
		}
	}
	for _, bad := range []string{"<script", "src=\"http", "@import"} {
		if strings.Contains(body, bad) {
			t.Errorf("install page contains %q", bad)
		}
	}
}

func TestRedirects(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), nil, time.Now())
	tests := []struct {
		name   string
		h      http.Handler
		method string
		url    string
		want   string
	}{
		{"selfca path+query", newInstallHandler(ca, "8443", "8080"), "GET", "http://tincan.lan:8080/r/abc?x=1&y=%2F", "https://tincan.lan:8443/r/abc?x=1&y=%2F"},
		{"selfca root", newInstallHandler(ca, "443", "80"), "GET", "http://tincan.lan/", "https://tincan.lan/"},
		{"selfca POST to install", newInstallHandler(ca, "443", "80"), "POST", "http://tincan.lan/install", "https://tincan.lan/install"},
		{"escaped path", RedirectHandler("443"), "GET", "http://example.com/a%2Fb/c?q", "https://example.com/a%2Fb/c?q"},
		{"ipv6", RedirectHandler("8443"), "GET", "http://[fd00::1]:8080/x", "https://[fd00::1]:8443/x"},
		{"ipv6 default port", RedirectHandler("443"), "GET", "http://[fd00::1]/x", "https://[fd00::1]/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.url, nil))
			if rec.Code != http.StatusPermanentRedirect {
				t.Fatalf("status %d", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != tt.want {
				t.Errorf("Location %q, want %q", loc, tt.want)
			}
		})
	}
}

func TestInstallURL(t *testing.T) {
	cases := map[[2]string]string{
		{"tincan.lan:8443", "8080"}: "http://tincan.lan:8080/install",
		{"tincan.lan", "80"}:        "http://tincan.lan/install",
		{"[fd00::1]:443", "80"}:     "http://[fd00::1]/install",
	}
	for in, want := range cases {
		if got := InstallURL(in[0], in[1]); got != want {
			t.Errorf("InstallURL(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}

func TestFilesModeReload(t *testing.T) {
	dir := t.TempDir()
	// Use selfca to mint two different certificate pairs.
	a := newTestCA(t, filepath.Join(dir, "a"), []string{"a.lan"}, time.Now())
	b := newTestCA(t, filepath.Join(dir, "b"), []string{"b.lan"}, time.Now())
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	cp := func(src *selfCA) {
		for from, to := range map[string]string{serverCertFile: certPath, serverKeyFile: keyPath} {
			data, err := os.ReadFile(src.path(from))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(to, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cp(a)
	r, err := newFileReloader(certPath, keyPath, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetCertificate(&tls.ClientHelloInfo{})
	if got.Leaf.DNSNames[0] != "a.lan" {
		t.Fatalf("got %v", got.Leaf.DNSNames)
	}
	cp(b)
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetCertificate(&tls.ClientHelloInfo{})
	if got.Leaf.DNSNames[0] != "b.lan" {
		t.Fatalf("after reload got %v", got.Leaf.DNSNames)
	}
	// A broken file keeps the previous certificate.
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(); err == nil {
		t.Fatal("expected reload error")
	}
	got, _ = r.GetCertificate(&tls.ClientHelloInfo{})
	if got.Leaf.DNSNames[0] != "b.lan" {
		t.Fatal("certificate lost after failed reload")
	}
}
