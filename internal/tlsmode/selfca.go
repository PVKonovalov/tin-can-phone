package tlsmode

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
)

const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"

	caValidity      = 10 * 365 * 24 * time.Hour
	serverValidity  = 397 * 24 * time.Hour // max accepted by Apple/Chrome for leaf certificates
	renewBefore     = 30 * 24 * time.Hour
	backdate        = time.Hour // tolerate client clock skew
	maintainEvery   = 12 * time.Hour
	dirPerm         = 0o700
	filePerm        = 0o600
	alwaysDNSName   = "localhost"
	alwaysIPAddress = "127.0.0.1"
)

type selfCAOptions struct {
	Dir  string
	SANs []string
	// Permitted are the CA name constraints. SANs outside them are rejected
	// by config validation; the implicit localhost/127.0.0.1 are added only
	// when permitted.
	Permitted config.Permitted
	Hostname  string
	Log       *slog.Logger
	Now       func() time.Time // defaults to time.Now
}

// selfCA owns a local CA and the server certificate it signs.
type selfCA struct {
	opts   selfCAOptions
	caCert *x509.Certificate
	caKey  crypto.Signer
	dns    []string
	ips    []net.IP

	mu     sync.RWMutex
	server *tls.Certificate
}

// openSelfCA loads the CA from opts.Dir (creating it on first start) and makes
// sure a valid server certificate for opts.SANs exists.
func openSelfCA(opts selfCAOptions) (*selfCA, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Hostname == "" {
		opts.Hostname = "unknown-host"
	}
	if err := os.MkdirAll(opts.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("selfca: %w", err)
	}
	if err := os.Chmod(opts.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("selfca: %w", err)
	}

	ca := &selfCA{opts: opts}
	ca.dns, ca.ips = splitSANs(opts.SANs, opts.Permitted)
	if len(ca.dns)+len(ca.ips) == 0 {
		return nil, fmt.Errorf("selfca: no server certificate names: set %sSELFCA_SANS or permit localhost", config.Prefix)
	}
	if err := ca.loadOrCreateCA(); err != nil {
		return nil, err
	}
	if err := ca.ensureServerCert(); err != nil {
		return nil, err
	}
	return ca, nil
}

// splitSANs returns the de-duplicated DNS names and IPs, including localhost
// and 127.0.0.1 when the name constraints permit them. Both lists are sorted.
func splitSANs(sans []string, perm config.Permitted) ([]string, []net.IP) {
	dnsSet := map[string]bool{}
	ipSet := map[string]net.IP{}
	if perm.Contains(alwaysDNSName) {
		dnsSet[alwaysDNSName] = true
	}
	if perm.Contains(alwaysIPAddress) {
		ipSet[alwaysIPAddress] = net.ParseIP(alwaysIPAddress)
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ipSet[ip.String()] = ip
		} else if s != "" {
			dnsSet[strings.ToLower(s)] = true
		}
	}
	dns := make([]string, 0, len(dnsSet))
	for d := range dnsSet {
		dns = append(dns, d)
	}
	slices.Sort(dns)
	keys := make([]string, 0, len(ipSet))
	for k := range ipSet {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	ips := make([]net.IP, 0, len(keys))
	for _, k := range keys {
		ips = append(ips, ipSet[k])
	}
	return dns, ips
}

func (ca *selfCA) path(name string) string { return filepath.Join(ca.opts.Dir, name) }

func (ca *selfCA) loadOrCreateCA() error {
	certPEM, certErr := os.ReadFile(ca.path(caCertFile))
	keyPEM, keyErr := os.ReadFile(ca.path(caKeyFile))
	switch {
	case certErr == nil && keyErr == nil:
		cert, key, err := parsePair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("selfca: existing CA in %s is unusable (remove the directory to create a new CA): %w", ca.opts.Dir, err)
		}
		if !cert.IsCA {
			return fmt.Errorf("selfca: %s is not a CA certificate", ca.path(caCertFile))
		}
		if err := ca.checkConstraints(cert); err != nil {
			return err
		}
		if ca.opts.Now().After(cert.NotAfter) {
			return fmt.Errorf("selfca: CA expired on %s; remove %s to create a new one (clients must reinstall it)", cert.NotAfter, ca.opts.Dir)
		}
		ca.fixPerm(caKeyFile)
		ca.caCert, ca.caKey = cert, key
		ca.opts.Log.Info("selfca: reusing existing CA", "dir", ca.opts.Dir)
		return nil
	case certErr == nil && errors.Is(keyErr, fs.ErrNotExist):
		// Refuse to silently replace a CA that clients may already trust.
		return fmt.Errorf("selfca: %s exists but %s is missing; restore the key or remove the directory", caCertFile, caKeyFile)
	case certErr != nil && !errors.Is(certErr, fs.ErrNotExist):
		return fmt.Errorf("selfca: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist):
		return fmt.Errorf("selfca: %w", keyErr)
	}
	// No CA certificate yet (a stray key from an interrupted first start is overwritten).
	return ca.createCA()
}

func (ca *selfCA) createCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := ca.opts.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "tin-can-phone local CA " + ca.opts.Hostname,
			Organization: []string{"tin-can-phone"},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ca.applyConstraints(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("selfca: create CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	// Key first: a crash between the two writes leaves no ca.crt, so the next
	// start simply creates a new CA.
	if err := ca.writeKey(caKeyFile, key); err != nil {
		return err
	}
	if err := ca.writeFile(caCertFile, pemCert(der)); err != nil {
		return err
	}
	ca.caCert, ca.caKey = cert, key
	ca.opts.Log.Info("selfca: created new CA", "dir", ca.opts.Dir, "subject", cert.Subject.CommonName)
	return nil
}

// applyConstraints sets the X.509 name constraints from opts.Permitted.
// Constraints apply per name type, so without any CIDR all IPs are excluded.
func (ca *selfCA) applyConstraints(tmpl *x509.Certificate) {
	want := ca.wantConstraints()
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = want.dns
	tmpl.PermittedIPRanges = want.permittedIPs
	tmpl.ExcludedIPRanges = want.excludedIPs
}

type constraints struct {
	dns          []string
	permittedIPs []*net.IPNet
	excludedIPs  []*net.IPNet
	critical     bool
	eku          []x509.ExtKeyUsage
}

func (c constraints) String() string {
	return fmt.Sprintf("dns=%v permitted_ips=%v excluded_ips=%v critical=%v server_auth_eku=%v",
		c.dns, netStrings(c.permittedIPs), netStrings(c.excludedIPs), c.critical,
		slices.Equal(c.eku, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
}

func (c constraints) equal(o constraints) bool {
	return slices.Equal(sortedCopy(c.dns), sortedCopy(o.dns)) &&
		slices.Equal(sortedCopy(netStrings(c.permittedIPs)), sortedCopy(netStrings(o.permittedIPs))) &&
		slices.Equal(sortedCopy(netStrings(c.excludedIPs)), sortedCopy(netStrings(o.excludedIPs))) &&
		c.critical == o.critical && slices.Equal(c.eku, o.eku)
}

func (ca *selfCA) wantConstraints() constraints {
	c := constraints{
		dns:          slices.Clone(ca.opts.Permitted.DNS),
		permittedIPs: slices.Clone(ca.opts.Permitted.Nets),
		critical:     true,
		eku:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(c.permittedIPs) == 0 {
		c.excludedIPs = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	return c
}

func haveConstraints(cert *x509.Certificate) constraints {
	return constraints{
		dns:          cert.PermittedDNSDomains,
		permittedIPs: cert.PermittedIPRanges,
		excludedIPs:  cert.ExcludedIPRanges,
		critical:     cert.PermittedDNSDomainsCritical,
		eku:          cert.ExtKeyUsage,
	}
}

// checkConstraints refuses an existing CA whose name constraints differ from
// the configuration. A trusted CA is never replaced silently.
func (ca *selfCA) checkConstraints(cert *x509.Certificate) error {
	have, want := haveConstraints(cert), ca.wantConstraints()
	if have.equal(want) {
		return nil
	}
	return fmt.Errorf("selfca: the existing CA in %s has different name constraints than %sSELFCA_PERMITTED\n"+
		"  CA has:      %s\n  config wants: %s\n"+
		"The CA must be recreated: delete %s, restart, and reinstall the new CA on every device",
		ca.opts.Dir, config.Prefix, have, want, ca.opts.Dir)
}

// PermittedDescription returns the permitted DNS suffixes and IP ranges.
func (ca *selfCA) PermittedDescription() (dns, ips []string) {
	c := haveConstraints(ca.caCert)
	return c.dns, netStrings(c.permittedIPs)
}

func netStrings(ns []*net.IPNet) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.String()
	}
	return out
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// ensureServerCert loads the server certificate and re-issues it if it is
// missing, invalid, not signed by the CA, expiring soon or has other SANs.
func (ca *selfCA) ensureServerCert() error {
	reason := ""
	certPEM, err1 := os.ReadFile(ca.path(serverCertFile))
	keyPEM, err2 := os.ReadFile(ca.path(serverKeyFile))
	var cert *x509.Certificate
	var key crypto.Signer
	if err := errors.Join(err1, err2); err != nil {
		reason = "missing"
	} else if cert, key, err = parsePair(certPEM, keyPEM); err != nil {
		reason = "unreadable: " + err.Error()
	} else {
		reason = ca.checkServerCert(cert)
	}

	if reason == "" {
		ca.fixPerm(serverKeyFile)
		ca.setServer(cert, key)
		return nil
	}
	ca.opts.Log.Info("selfca: issuing server certificate", "reason", reason, "dns", ca.dns, "ips", ca.ips)
	return ca.issueServerCert()
}

// checkServerCert returns why cert must be re-issued, or "" if it is fine.
func (ca *selfCA) checkServerCert(cert *x509.Certificate) string {
	now := ca.opts.Now()
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return "does not verify against CA: " + err.Error()
	}
	if cert.NotAfter.Sub(now) < renewBefore && cert.NotAfter.Before(ca.caCert.NotAfter) {
		return "expires " + cert.NotAfter.Format(time.RFC3339)
	}
	gotDNS := slices.Clone(cert.DNSNames)
	slices.Sort(gotDNS)
	gotIPs := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		gotIPs[i] = ip.String()
	}
	slices.Sort(gotIPs)
	wantIPs := make([]string, len(ca.ips))
	for i, ip := range ca.ips {
		wantIPs[i] = ip.String()
	}
	if !slices.Equal(gotDNS, ca.dns) || !slices.Equal(gotIPs, wantIPs) {
		return fmt.Sprintf("SANs changed (had dns=%v ips=%v)", gotDNS, gotIPs)
	}
	return ""
}

func (ca *selfCA) issueServerCert() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := ca.opts.Now()
	notAfter := now.Add(serverValidity)
	if notAfter.After(ca.caCert.NotAfter) {
		notAfter = ca.caCert.NotAfter
		ca.opts.Log.Warn("selfca: CA expires soon; server certificate validity is limited by it",
			"ca_not_after", ca.caCert.NotAfter)
	}
	// CN is informational (browsers use SANs): prefer a real DNS name.
	cn := alwaysDNSName
	if i := slices.IndexFunc(ca.dns, func(d string) bool { return d != alwaysDNSName }); i >= 0 {
		cn = ca.dns[i]
	} else if len(ca.dns) == 0 && len(ca.ips) > 0 {
		cn = ca.ips[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"tin-can-phone"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              ca.dns,
		IPAddresses:           ca.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, key.Public(), ca.caKey)
	if err != nil {
		return fmt.Errorf("selfca: issue server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := ca.writeKey(serverKeyFile, key); err != nil {
		return err
	}
	if err := ca.writeFile(serverCertFile, pemCert(der)); err != nil {
		return err
	}
	ca.setServer(cert, key)
	return nil
}

func (ca *selfCA) setServer(cert *x509.Certificate, key crypto.Signer) {
	tc := &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	ca.mu.Lock()
	ca.server = tc
	ca.mu.Unlock()
}

// GetCertificate implements tls.Config.GetCertificate.
func (ca *selfCA) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.server, nil
}

// maintain periodically re-issues the server certificate before it expires,
// so long-running processes do not serve an expired certificate.
func (ca *selfCA) maintain(ctx context.Context) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ca.mu.RLock()
			leaf := ca.server.Leaf
			ca.mu.RUnlock()
			if reason := ca.checkServerCert(leaf); reason != "" {
				ca.opts.Log.Info("selfca: renewing server certificate", "reason", reason)
				if err := ca.issueServerCert(); err != nil {
					ca.opts.Log.Error("selfca: renewal failed", "err", err)
				}
			}
		}
	}
}

// CACertDER returns the CA certificate in DER form.
func (ca *selfCA) CACertDER() []byte { return ca.caCert.Raw }

// CACertPEM returns the CA certificate in PEM form.
func (ca *selfCA) CACertPEM() []byte { return pemCert(ca.caCert.Raw) }

// Fingerprint returns the SHA-256 fingerprint of the CA certificate as
// colon-separated upper-case hex.
func (ca *selfCA) Fingerprint() string {
	sum := sha256.Sum256(ca.caCert.Raw)
	var b strings.Builder
	for i, c := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", c)
	}
	return b.String()
}

func (ca *selfCA) writeKey(name string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return ca.writeFile(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// writeFile atomically writes data to name with mode 0600.
func (ca *selfCA) writeFile(name string, data []byte) error {
	f, err := os.CreateTemp(ca.opts.Dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("selfca: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(filePerm); err != nil {
		f.Close()
		return fmt.Errorf("selfca: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("selfca: write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("selfca: write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("selfca: write %s: %w", name, err)
	}
	if err := os.Rename(tmp, ca.path(name)); err != nil {
		return fmt.Errorf("selfca: %w", err)
	}
	return nil
}

// fixPerm tightens permissions of an existing private key file.
func (ca *selfCA) fixPerm(name string) {
	p := ca.path(name)
	if st, err := os.Stat(p); err == nil && st.Mode().Perm() != filePerm {
		ca.opts.Log.Warn("selfca: fixing key file permissions", "file", p, "was", st.Mode().Perm())
		_ = os.Chmod(p, filePerm)
	}
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("no PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("private key is not a signer")
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, errors.New("private key does not match certificate")
	}
	return cert, key, nil
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return n.Add(n, big.NewInt(1)) // never zero
}
