package config

import (
	"slices"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[strings.TrimPrefix(k, Prefix)] }
}

func TestLoadValid(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string
		check func(t *testing.T, c *Config)
	}{
		{
			name: "files",
			env:  map[string]string{"TLS_MODE": "files", "TLS_CERT": "/etc/c.pem", "TLS_KEY": "/etc/k.pem"},
			check: func(t *testing.T, c *Config) {
				if c.HTTPSAddr != ":443" || c.HTTPAddr != ":80" {
					t.Errorf("defaults not applied: %q %q", c.HTTPSAddr, c.HTTPAddr)
				}
				if c.TLSCert != "/etc/c.pem" || c.TLSKey != "/etc/k.pem" {
					t.Errorf("cert/key: %q %q", c.TLSCert, c.TLSKey)
				}
			},
		},
		{
			name: "acme",
			env: map[string]string{
				"TLS_MODE": "ACME", "ACME_DOMAINS": "call.example.com, Talk.Example.com.",
				"ACME_EMAIL": "ops@example.com", "PUBLIC_URL": "https://call.example.com/",
			},
			check: func(t *testing.T, c *Config) {
				if c.TLSMode != ModeACME {
					t.Errorf("mode %q", c.TLSMode)
				}
				if !slices.Equal(c.ACMEDomains, []string{"call.example.com", "talk.example.com"}) {
					t.Errorf("domains %v", c.ACMEDomains)
				}
				if c.ACMECacheDir != DefaultACMECacheDir {
					t.Errorf("cache dir %q", c.ACMECacheDir)
				}
				if c.PublicURL != "https://call.example.com" {
					t.Errorf("public url %q", c.PublicURL)
				}
			},
		},
		{
			name: "selfca",
			env: map[string]string{
				"TLS_MODE": "selfca", "HTTPS_ADDR": "127.0.0.1:8443", "HTTP_ADDR": ":8080",
				"SELFCA_DIR": "/tmp/ca", "SELFCA_SANS": "192.168.1.10,tincan.lan fd00::1",
			},
			check: func(t *testing.T, c *Config) {
				if !slices.Equal(c.SelfCASANs, []string{"192.168.1.10", "tincan.lan", "fd00::1"}) {
					t.Errorf("sans %v", c.SelfCASANs)
				}
				if c.HTTPSPort() != "8443" || c.HTTPPort() != "8080" {
					t.Errorf("ports %q %q", c.HTTPSPort(), c.HTTPPort())
				}
			},
		},
		{
			name: "selfca defaults",
			env:  map[string]string{"TLS_MODE": "selfca"},
			check: func(t *testing.T, c *Config) {
				if c.SelfCADir != DefaultSelfCADir || len(c.SelfCASANs) != 0 {
					t.Errorf("got %q %v", c.SelfCADir, c.SelfCASANs)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load(env(tt.env))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.check(t, c)
			if len(c.LogAttrs()) == 0 {
				t.Error("no log attrs")
			}
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string // substrings that must all appear in the error
	}{
		{"no mode", map[string]string{}, []string{"TINCAN_TLS_MODE: required"}},
		{"unknown mode", map[string]string{"TLS_MODE": "magic"}, []string{`unknown mode "magic"`}},
		{
			"files missing both",
			map[string]string{"TLS_MODE": "files"},
			[]string{"TINCAN_TLS_CERT: required", "TINCAN_TLS_KEY: required"},
		},
		{
			"files missing key",
			map[string]string{"TLS_MODE": "files", "TLS_CERT": "c.pem"},
			[]string{"TINCAN_TLS_KEY: required"},
		},
		{"acme no domains", map[string]string{"TLS_MODE": "acme"}, []string{"TINCAN_ACME_DOMAINS: at least one"}},
		{
			"acme bad domains and email",
			map[string]string{"TLS_MODE": "acme", "ACME_DOMAINS": "10.0.0.1,bad_name.com,*.example.com", "ACME_EMAIL": "nope"},
			[]string{`"10.0.0.1" is an IP`, `"bad_name.com" is not a valid`, `"*.example.com" is not a valid`, "TINCAN_ACME_EMAIL"},
		},
		{
			"selfca bad san",
			map[string]string{"TLS_MODE": "selfca", "SELFCA_SANS": "ok.lan,-bad-,a..b"},
			[]string{`"-bad-"`, `"a..b"`},
		},
		{
			"everything wrong at once",
			map[string]string{
				"TLS_MODE": "files", "HTTPS_ADDR": "443", "HTTP_ADDR": ":99999",
				"PUBLIC_URL": "http://example.com/path",
			},
			[]string{"TINCAN_HTTPS_ADDR", "TINCAN_HTTP_ADDR", "TINCAN_PUBLIC_URL", "TINCAN_TLS_CERT", "TINCAN_TLS_KEY"},
		},
		{
			"public url with path",
			map[string]string{"TLS_MODE": "selfca", "PUBLIC_URL": "https://example.com/x"},
			[]string{"TINCAN_PUBLIC_URL: must contain only"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load(env(tt.env))
			if err == nil {
				t.Fatalf("expected error, got config %+v", c)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not mention %q", err, w)
				}
			}
			if got, want := strings.Count(err.Error(), "\n")+1, len(tt.want); got < want {
				t.Errorf("got %d errors, want at least %d: %v", got, want, err)
			}
		})
	}
}

func TestIrrelevantSettingsIgnored(t *testing.T) {
	// files-mode variables must not be required (or validated) in selfca mode and vice versa.
	_, err := Load(env(map[string]string{"TLS_MODE": "selfca", "ACME_DOMAINS": "10.0.0.1"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
