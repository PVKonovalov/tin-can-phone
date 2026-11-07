// Package config parses and validates TINCAN_* environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
)

// Prefix is prepended to every environment variable name.
const Prefix = "TINCAN_"

// TLSMode selects how the HTTPS certificate is obtained.
type TLSMode string

const (
	ModeACME   TLSMode = "acme"
	ModeFiles  TLSMode = "files"
	ModeSelfCA TLSMode = "selfca"
)

// Defaults for optional variables.
const (
	DefaultHTTPSAddr    = ":443"
	DefaultHTTPAddr     = ":80"
	DefaultACMECacheDir = ".data/acme"
	DefaultSelfCADir    = ".data/selfca"
)

// Config is the effective server configuration.
type Config struct {
	PublicURL string // optional; external base URL (https://host[:port])

	HTTPSAddr string
	HTTPAddr  string

	TLSMode TLSMode

	// files mode
	TLSCert string
	TLSKey  string

	// acme mode
	ACMEDomains  []string
	ACMEEmail    string
	ACMECacheDir string

	// selfca mode
	SelfCADir  string
	SelfCASANs []string // DNS names and IP literals, as configured (without implicit localhost/127.0.0.1)
}

// Load reads the configuration using getenv (normally os.Getenv) and validates
// it. All validation problems are returned together, joined with errors.Join.
func Load(getenv func(string) string) (*Config, error) {
	get := func(name string) string { return strings.TrimSpace(getenv(Prefix + name)) }
	or := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}

	c := &Config{
		PublicURL:    strings.TrimRight(get("PUBLIC_URL"), "/"),
		HTTPSAddr:    or(get("HTTPS_ADDR"), DefaultHTTPSAddr),
		HTTPAddr:     or(get("HTTP_ADDR"), DefaultHTTPAddr),
		TLSMode:      TLSMode(strings.ToLower(get("TLS_MODE"))),
		TLSCert:      get("TLS_CERT"),
		TLSKey:       get("TLS_KEY"),
		ACMEDomains:  splitList(get("ACME_DOMAINS")),
		ACMEEmail:    get("ACME_EMAIL"),
		ACMECacheDir: or(get("ACME_CACHE_DIR"), DefaultACMECacheDir),
		SelfCADir:    or(get("SELFCA_DIR"), DefaultSelfCADir),
		SelfCASANs:   splitList(get("SELFCA_SANS")),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks the configuration and returns every problem found.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		switch {
		case err != nil:
			add("%sPUBLIC_URL: %v", Prefix, err)
		case u.Scheme != "https" || u.Host == "":
			add("%sPUBLIC_URL: must be an absolute https:// URL, got %q", Prefix, c.PublicURL)
		case u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
			add("%sPUBLIC_URL: must contain only scheme, host and optional port, got %q", Prefix, c.PublicURL)
		}
	}

	if err := validateAddr(c.HTTPSAddr); err != nil {
		add("%sHTTPS_ADDR: %v", Prefix, err)
	}
	if err := validateAddr(c.HTTPAddr); err != nil {
		add("%sHTTP_ADDR: %v", Prefix, err)
	}

	switch c.TLSMode {
	case ModeFiles:
		if c.TLSCert == "" {
			add("%sTLS_CERT: required when %sTLS_MODE=files", Prefix, Prefix)
		}
		if c.TLSKey == "" {
			add("%sTLS_KEY: required when %sTLS_MODE=files", Prefix, Prefix)
		}
	case ModeACME:
		if len(c.ACMEDomains) == 0 {
			add("%sACME_DOMAINS: at least one domain required when %sTLS_MODE=acme", Prefix, Prefix)
		}
		for _, d := range c.ACMEDomains {
			if net.ParseIP(d) != nil {
				add("%sACME_DOMAINS: %q is an IP address; ACME needs DNS names", Prefix, d)
			} else if !validDNSName(d) {
				add("%sACME_DOMAINS: %q is not a valid DNS name", Prefix, d)
			}
		}
		if c.ACMEEmail != "" {
			if _, err := mail.ParseAddress(c.ACMEEmail); err != nil {
				add("%sACME_EMAIL: %q is not a valid e-mail address", Prefix, c.ACMEEmail)
			}
		}
		if c.ACMECacheDir == "" {
			add("%sACME_CACHE_DIR: must not be empty", Prefix)
		}
	case ModeSelfCA:
		if c.SelfCADir == "" {
			add("%sSELFCA_DIR: must not be empty", Prefix)
		}
		for _, s := range c.SelfCASANs {
			if net.ParseIP(s) == nil && !validDNSName(s) {
				add("%sSELFCA_SANS: %q is neither an IP address nor a valid DNS name", Prefix, s)
			}
		}
	case "":
		add("%sTLS_MODE: required (acme | files | selfca)", Prefix)
	default:
		add("%sTLS_MODE: unknown mode %q (want acme | files | selfca)", Prefix, c.TLSMode)
	}

	return errors.Join(errs...)
}

// HTTPSPort returns the port part of HTTPSAddr.
func (c *Config) HTTPSPort() string { return portOf(c.HTTPSAddr) }

// HTTPPort returns the port part of HTTPAddr.
func (c *Config) HTTPPort() string { return portOf(c.HTTPAddr) }

// LogAttrs returns the effective configuration for logging. Only settings
// relevant to the selected TLS mode are included. The configuration holds no
// secret values (key material is referenced by path only).
func (c *Config) LogAttrs() []any {
	attrs := []any{
		slog.String("tls_mode", string(c.TLSMode)),
		slog.String("https_addr", c.HTTPSAddr),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("public_url", c.PublicURL),
	}
	switch c.TLSMode {
	case ModeFiles:
		attrs = append(attrs, slog.String("tls_cert", c.TLSCert), slog.String("tls_key", c.TLSKey))
	case ModeACME:
		attrs = append(attrs,
			slog.Any("acme_domains", c.ACMEDomains),
			slog.String("acme_email", c.ACMEEmail),
			slog.String("acme_cache_dir", c.ACMECacheDir))
	case ModeSelfCA:
		attrs = append(attrs,
			slog.String("selfca_dir", c.SelfCADir),
			slog.Any("selfca_sans", c.SelfCASANs))
	}
	return attrs
}

func splitList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		f = strings.ToLower(strings.TrimSuffix(f, "."))
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func validateAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: %v", addr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q: port must be 1-65535", addr)
	}
	return nil
}

func portOf(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// validDNSName reports whether s is a syntactically valid (non-wildcard) DNS name.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
