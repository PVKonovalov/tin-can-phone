package config

import (
	"slices"
	"strings"
	"testing"
	"time"
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
				"SELFCA_PERMITTED": "tincan.lan,localhost,192.168.0.0/16,fd00::/8",
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
			env:  map[string]string{"TLS_MODE": "selfca", "SELFCA_PERMITTED": "localhost"},
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
	_, err := Load(env(map[string]string{"TLS_MODE": "selfca", "SELFCA_PERMITTED": "localhost", "ACME_DOMAINS": "10.0.0.1"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelfCAPermitted(t *testing.T) {
	base := func(kv ...string) map[string]string {
		m := map[string]string{"TLS_MODE": "selfca"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	bad := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"missing", base(), []string{"TINCAN_SELFCA_PERMITTED: required"}},
		{"only cidrs", base("SELFCA_PERMITTED", "10.0.0.0/8"), []string{"at least one DNS suffix"}},
		{"bad entries", base("SELFCA_PERMITTED", "localhost,10.0.0.0/33,10.1.1.1,bad_name"),
			[]string{`"10.0.0.0/33"`, `"10.1.1.1" is an IP address`, `"bad_name"`}},
		{"sans outside", base("SELFCA_PERMITTED", "tincan.lan,localhost,192.168.0.0/16",
			"SELFCA_SANS", "a.tincan.lan,192.168.1.5,example.com,10.0.0.1,tincan.lan.evil.com"),
			[]string{`"example.com", "10.0.0.1", "tincan.lan.evil.com" outside TINCAN_SELFCA_PERMITTED`}},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(env(tt.env))
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			if strings.Contains(err.Error(), "a.tincan.lan") || strings.Contains(err.Error(), "192.168.1.5") {
				t.Errorf("permitted SAN reported: %v", err)
			}
		})
	}

	c, err := Load(env(base("SELFCA_PERMITTED", "tincan.lan,localhost,127.0.0.0/8,::1/128", "SELFCA_SANS", "x.tincan.lan,127.0.0.2,::1")))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePermitted(c.SelfCAPermitted)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DNS) != 2 || len(p.Nets) != 2 {
		t.Errorf("parsed %+v", p)
	}
	for name, want := range map[string]bool{
		"tincan.lan": true, "a.b.tincan.lan": true, "localhost": true, "TINCAN.LAN.": true,
		"xtincan.lan": false, "tincan.lan.com": false, "127.1.2.3": true, "::1": true, "::2": false, "10.0.0.1": false,
	} {
		if got := p.Contains(name); got != want {
			t.Errorf("Contains(%q)=%v want %v", name, got, want)
		}
	}
}

func TestRoomSettings(t *testing.T) {
	c, err := Load(env(map[string]string{"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxPeers != 8 || c.MaxRooms != 1000 || c.RoomTTL != 30*time.Minute || c.PublicHTTPPort != "80" || c.AllowedOrigins != nil {
		t.Errorf("defaults: %+v", c)
	}

	c, err = Load(env(map[string]string{
		"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k",
		"MAX_PEERS": "32", "MAX_ROOMS": "5", "ROOM_TTL": "90s", "PUBLIC_HTTP_PORT": "8080",
		"PUBLIC_URL": "https://Call.Example.com:443",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxPeers != 32 || c.MaxRooms != 5 || c.RoomTTL != 90*time.Second || c.PublicHTTPPort != "8080" {
		t.Errorf("values: %+v", c)
	}
	if !slices.Equal(c.AllowedOrigins, []string{"https://call.example.com"}) {
		t.Errorf("origins default from PUBLIC_URL: %v", c.AllowedOrigins)
	}

	c, err = Load(env(map[string]string{
		"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k", "PUBLIC_URL": "https://a.example.com",
		"ALLOWED_ORIGINS": "https://B.example.com:443, http://localhost:8080,https://[fd00::1]:8443",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://b.example.com", "http://localhost:8080", "https://[fd00::1]:8443"}; !slices.Equal(c.AllowedOrigins, want) {
		t.Errorf("origins %v want %v", c.AllowedOrigins, want)
	}

	_, err = Load(env(map[string]string{
		"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k",
		"MAX_PEERS": "1", "MAX_ROOMS": "0", "ROOM_TTL": "soon", "PUBLIC_HTTP_PORT": "0",
		"ALLOWED_ORIGINS": "https://ok.example.com,ftp://x,https://a.com/path",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, w := range []string{"TINCAN_MAX_PEERS", "TINCAN_MAX_ROOMS", "TINCAN_ROOM_TTL", "TINCAN_PUBLIC_HTTP_PORT", `"ftp://x"`, `"https://a.com/path"`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %s: %v", w, err)
		}
	}
	if _, err := Load(env(map[string]string{"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k", "MAX_PEERS": "33"})); err == nil {
		t.Error("MAX_PEERS=33 accepted")
	}
}

func TestMediaSettings(t *testing.T) {
	base := map[string]string{"TLS_MODE": "files", "TLS_CERT": "c", "TLS_KEY": "k"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	c, err := Load(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.MediaPort != 50000 || len(c.AdvertiseIPs) != 0 {
		t.Errorf("defaults %d %v", c.MediaPort, c.AdvertiseIPs)
	}
	c, err = Load(env(with("MEDIA_PORT", "40000", "ADVERTISE_IPS", "203.0.113.5, 192.168.1.10,2001:db8::1")))
	if err != nil {
		t.Fatal(err)
	}
	if c.MediaPort != 40000 || !slices.Equal(c.AdvertiseIPs, []string{"203.0.113.5", "192.168.1.10", "2001:db8::1"}) {
		t.Errorf("got %d %v", c.MediaPort, c.AdvertiseIPs)
	}

	for _, tt := range []struct {
		env  map[string]string
		want []string
	}{
		{with("MEDIA_PORT", "0"), []string{"TINCAN_MEDIA_PORT: 0 out of range"}},
		{with("MEDIA_PORT", "70000"), []string{"TINCAN_MEDIA_PORT: 70000 out of range"}},
		{with("MEDIA_PORT", "x"), []string{"TINCAN_MEDIA_PORT"}},
		{with("MEDIA_PORT", "443"), []string{"must differ from the HTTP(S) listen ports"}},
		{with("MEDIA_PORT", "8080", "HTTP_ADDR", ":8080"), []string{"must differ"}},
		{with("ADVERTISE_IPS", "10.0.0.1,host.lan,0.0.0.0,10.0.0.1,::0:1,::1,224.0.0.1"),
			[]string{`"host.lan" is not an IP`, `"0.0.0.0" is not a unicast`, `"10.0.0.1" duplicates`, `"::1" duplicates "::0:1"`, `"224.0.0.1" is not a unicast`}},
	} {
		_, err := Load(env(tt.env))
		if err == nil {
			t.Errorf("%v: expected error", tt.env)
			continue
		}
		for _, w := range tt.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("error %q lacks %q", err, w)
			}
		}
	}
}
