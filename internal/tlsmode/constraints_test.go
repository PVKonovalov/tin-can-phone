package tlsmode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signLeaf issues a leaf for the given names directly with the CA key,
// bypassing every check in selfca (as an attacker holding ca.key would).
func signLeaf(t *testing.T, ca *selfCA, names ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, key.Public(), ca.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verify(ca *selfCA, leaf *x509.Certificate, name string) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name})
	return err
}

func TestCAHasNameConstraints(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), nil, time.Now())
	c := ca.caCert
	if !c.PermittedDNSDomainsCritical {
		t.Error("constraints not critical")
	}
	if len(c.PermittedDNSDomains) == 0 || len(c.PermittedIPRanges) == 0 {
		t.Errorf("constraints missing: %v %v", c.PermittedDNSDomains, c.PermittedIPRanges)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("CA EKU %v", c.ExtKeyUsage)
	}
}

func TestConstraintsRejectOutsideNames(t *testing.T) {
	ca := newTestCA(t, t.TempDir(), []string{"tincan.lan", "192.168.1.10"}, time.Now())

	// Inside the zone (also a different name than the SANs): accepted.
	for _, n := range []string{"other.tincan.lan", "10.1.2.3"} {
		if err := verify(ca, signLeaf(t, ca, n), n); err != nil {
			t.Errorf("%s inside constraints rejected: %v", n, err)
		}
	}
	// Outside: rejected even though signed by the CA key.
	for _, n := range []string{"example.com", "8.8.8.8", "tincan.lan.evil.com"} {
		err := verify(ca, signLeaf(t, ca, n), n)
		if err == nil {
			t.Errorf("%s outside constraints verified", n)
		} else if _, ok := err.(x509.CertificateInvalidError); !ok {
			t.Errorf("%s: unexpected error type %T: %v", n, err, err)
		}
	}
	// A leaf mixing a permitted and a forbidden name is rejected as a whole.
	if err := verify(ca, signLeaf(t, ca, "x.tincan.lan", "example.com"), "x.tincan.lan"); err == nil {
		t.Error("leaf with an extra forbidden SAN verified")
	}
}

func TestConstraintsNoCIDRExcludesAllIPs(t *testing.T) {
	ca, err := openSelfCA(selfCAOptions{
		Dir: t.TempDir(), SANs: []string{"tincan.lan"},
		Permitted: testPermitted(t, "tincan.lan", "localhost"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.ips) != 0 {
		t.Errorf("server cert has IP SANs without permitted CIDRs: %v", ca.ips)
	}
	srv := ca.server.Leaf
	for _, n := range []string{"tincan.lan", "localhost"} {
		if err := verify(ca, srv, n); err != nil {
			t.Errorf("verify %s: %v", n, err)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.10", "::1"} {
		if err := verify(ca, signLeaf(t, ca, ip), ip); err == nil {
			t.Errorf("IP leaf %s verified with no permitted CIDR", ip)
		}
	}
}

func TestExistingCAWithDifferentConstraintsRefused(t *testing.T) {
	dir := t.TempDir()
	first := newTestCA(t, dir, nil, time.Now())

	// Same constraints (different order): reused.
	reordered := append([]string(nil), defaultPermitted...)
	for i, j := 0, len(reordered)-1; i < j; i, j = i+1, j-1 {
		reordered[i], reordered[j] = reordered[j], reordered[i]
	}
	again, err := openSelfCA(selfCAOptions{Dir: dir, Permitted: testPermitted(t, reordered...)})
	if err != nil {
		t.Fatalf("same constraints refused: %v", err)
	}
	if !bytes.Equal(first.CACertDER(), again.CACertDER()) {
		t.Fatal("CA replaced")
	}

	// Different constraints: refused, CA untouched.
	before, _ := os.ReadFile(filepath.Join(dir, caCertFile))
	_, err = openSelfCA(selfCAOptions{Dir: dir, SANs: []string{"other.lan"}, Permitted: testPermitted(t, "other.lan", "10.0.0.0/8")})
	if err == nil || !strings.Contains(err.Error(), "must be recreated") || !strings.Contains(err.Error(), dir) {
		t.Fatalf("expected refusal naming the dir, got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, caCertFile))
	if !bytes.Equal(before, after) {
		t.Error("CA file changed after refusal")
	}
}

func TestExistingUnconstrainedCARefused(t *testing.T) {
	// Simulate a step-1 CA: no constraints, no EKU.
	dir := t.TempDir()
	ca := &selfCA{opts: selfCAOptions{Dir: dir, Hostname: "old", Now: time.Now}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "old CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.writeKey(caKeyFile, key); err != nil {
		t.Fatal(err)
	}
	if err := ca.writeFile(caCertFile, pemCert(der)); err != nil {
		t.Fatal(err)
	}
	_, err = openSelfCA(selfCAOptions{Dir: dir, Permitted: testPermitted(t, defaultPermitted...)})
	if err == nil || !strings.Contains(err.Error(), "must be recreated") {
		t.Fatalf("unconstrained CA not refused: %v", err)
	}
}

func TestSANChangeWithinConstraintsReissuesOnly(t *testing.T) {
	dir := t.TempDir()
	first := newTestCA(t, dir, []string{"tincan.lan"}, time.Now())
	second := newTestCA(t, dir, []string{"new.tincan.lan", "10.9.8.7"}, time.Now())
	if !bytes.Equal(first.CACertDER(), second.CACertDER()) {
		t.Fatal("CA changed")
	}
	for _, n := range []string{"new.tincan.lan", "10.9.8.7"} {
		if err := verify(second, second.server.Leaf, n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}
