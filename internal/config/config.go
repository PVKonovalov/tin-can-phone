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
	"time"
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
	DefaultPublicHTTP   = "80"
	DefaultMaxPeers     = 8
	DefaultMaxRooms     = 1000
	DefaultRoomTTL      = 30 * time.Minute

	MinMaxPeers = 2
	MaxMaxPeers = 32
)

// Config is the effective server configuration.
type Config struct {
	PublicURL string // optional; external base URL (https://host[:port])
	// PublicHTTPPort is the external plain-HTTP port used to build the selfca
	// install link (default 80).
	PublicHTTPPort string

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
	// SelfCAPermitted are the CA name constraints: DNS suffixes and CIDRs.
	SelfCAPermitted []string

	// rooms and signaling
	MaxPeers int
	MaxRooms int
	RoomTTL  time.Duration
	// AllowedOrigins is the WebSocket Origin allow-list (normalized
	// scheme://host[:port]). Empty means "same host as the request".
	AllowedOrigins []string
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

	var errs []error
	intVar := func(name string, def int) int {
		v := get(name)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s%s: %q is not an integer", Prefix, name, v))
			return def
		}
		return n
	}
	durVar := func(name string, def time.Duration) time.Duration {
		v := get(name)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s%s: %q is not a duration (e.g. 30m, 1h)", Prefix, name, v))
			return def
		}
		return d
	}

	c := &Config{
		PublicURL:      strings.TrimRight(get("PUBLIC_URL"), "/"),
		PublicHTTPPort: or(get("PUBLIC_HTTP_PORT"), DefaultPublicHTTP),
		HTTPSAddr:      or(get("HTTPS_ADDR"), DefaultHTTPSAddr),
		HTTPAddr:       or(get("HTTP_ADDR"), DefaultHTTPAddr),
		TLSMode:        TLSMode(strings.ToLower(get("TLS_MODE"))),
		TLSCert:        get("TLS_CERT"),
		TLSKey:         get("TLS_KEY"),
		ACMEDomains:    splitList(get("ACME_DOMAINS")),
		ACMEEmail:      get("ACME_EMAIL"),
		ACMECacheDir:   or(get("ACME_CACHE_DIR"), DefaultACMECacheDir),
		SelfCADir:      or(get("SELFCA_DIR"), DefaultSelfCADir),
		SelfCASANs:     splitList(get("SELFCA_SANS")),

		SelfCAPermitted: splitList(get("SELFCA_PERMITTED")),
		MaxPeers:        intVar("MAX_PEERS", DefaultMaxPeers),
		MaxRooms:        intVar("MAX_ROOMS", DefaultMaxRooms),
		RoomTTL:         durVar("ROOM_TTL", DefaultRoomTTL),
	}
	var originErrs []error
	c.AllowedOrigins, originErrs = parseOrigins(splitListKeepCase(get("ALLOWED_ORIGINS")))
	errs = append(errs, originErrs...)
	if len(c.AllowedOrigins) == 0 && c.PublicURL != "" {
		if o, err := NormalizeOrigin(c.PublicURL); err == nil {
			c.AllowedOrigins = []string{o}
		}
	}
	if err := errors.Join(append(errs, c.Validate())...); err != nil {
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
	if c.PublicHTTPPort != "" {
		if n, err := strconv.Atoi(c.PublicHTTPPort); err != nil || n < 1 || n > 65535 {
			add("%sPUBLIC_HTTP_PORT: %q must be a port 1-65535", Prefix, c.PublicHTTPPort)
		}
	}
	if c.MaxPeers < MinMaxPeers || c.MaxPeers > MaxMaxPeers {
		add("%sMAX_PEERS: %d out of range %d-%d", Prefix, c.MaxPeers, MinMaxPeers, MaxMaxPeers)
	}
	if c.MaxRooms < 1 {
		add("%sMAX_ROOMS: must be at least 1, got %d", Prefix, c.MaxRooms)
	}
	if c.RoomTTL < time.Second {
		add("%sROOM_TTL: must be at least 1s, got %s", Prefix, c.RoomTTL)
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
		perm, err := ParsePermitted(c.SelfCAPermitted)
		switch {
		case len(c.SelfCAPermitted) == 0:
			add("%sSELFCA_PERMITTED: required when %sTLS_MODE=selfca (DNS suffixes and CIDRs, e.g. tincan.lan,localhost,192.168.0.0/16,127.0.0.0/8)", Prefix, Prefix)
		case err != nil:
			add("%sSELFCA_PERMITTED: %v", Prefix, err)
		default:
			var outside []string
			for _, s := range c.SelfCASANs {
				if (net.ParseIP(s) != nil || validDNSName(s)) && !perm.Contains(s) {
					outside = append(outside, s)
				}
			}
			if len(outside) > 0 {
				add("%sSELFCA_SANS: %s outside %sSELFCA_PERMITTED %v", Prefix, strings.Join(quoteAll(outside), ", "), Prefix, c.SelfCAPermitted)
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
		slog.Int("max_peers", c.MaxPeers),
		slog.Int("max_rooms", c.MaxRooms),
		slog.Duration("room_ttl", c.RoomTTL),
		slog.Any("allowed_origins", c.AllowedOrigins),
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
			slog.Any("selfca_sans", c.SelfCASANs),
			slog.Any("selfca_permitted", c.SelfCAPermitted),
			slog.String("public_http_port", c.PublicHTTPPort))
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

func splitListKeepCase(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}

func parseOrigins(list []string) ([]string, []error) {
	var out []string
	var errs []error
	for _, o := range list {
		n, err := NormalizeOrigin(o)
		if err != nil {
			errs = append(errs, fmt.Errorf("%sALLOWED_ORIGINS: %v", Prefix, err))
			continue
		}
		out = append(out, n)
	}
	return out, errs
}

// NormalizeOrigin returns origin as lower-case scheme://host[:port], without
// the default port for the scheme. Only http and https are accepted.
func NormalizeOrigin(origin string) (string, error) {
	u, err := url.Parse(strings.TrimRight(origin, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("%q is not an origin (want scheme://host[:port])", origin)
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// Permitted is a parsed selfca name-constraint set.
type Permitted struct {
	DNS  []string     // DNS suffixes (a name matches if equal to or a subdomain of an entry)
	Nets []*net.IPNet // permitted IP ranges
}

// ParsePermitted parses DNS suffixes and CIDRs. At least one DNS suffix is
// required.
func ParsePermitted(list []string) (Permitted, error) {
	var p Permitted
	var errs []error
	for _, e := range list {
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("%q is not a valid CIDR", e))
				continue
			}
			p.Nets = append(p.Nets, n)
			continue
		}
		if net.ParseIP(e) != nil {
			errs = append(errs, fmt.Errorf("%q is an IP address; use a CIDR such as %s/32", e, e))
			continue
		}
		if !validDNSName(e) {
			errs = append(errs, fmt.Errorf("%q is neither a CIDR nor a valid DNS suffix", e))
			continue
		}
		p.DNS = append(p.DNS, e)
	}
	if len(p.DNS) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("at least one DNS suffix is required (localhost counts)"))
	}
	return p, errors.Join(errs...)
}

// Contains reports whether name (a DNS name or IP literal) is permitted.
func (p Permitted) Contains(name string) bool {
	if ip := net.ParseIP(name); ip != nil {
		for _, n := range p.Nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range p.DNS {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
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
