package tlsmode

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PVKonovalov/tin-can-phone/internal/config"
)

var defaultPermitted = []string{"tincan.lan", "a.lan", "b.lan", "localhost", "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "fd00::/8"}

func testPermitted(t *testing.T, list ...string) config.Permitted {
	t.Helper()
	p, err := config.ParsePermitted(list)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestCA(t *testing.T, dir string, sans []string, now time.Time) *selfCA {
	t.Helper()
	ca, err := openSelfCA(selfCAOptions{
		Dir: dir, SANs: sans, Hostname: "testhost", Permitted: testPermitted(t, defaultPermitted...),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("openSelfCA: %v", err)
	}
	return ca
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s: no PEM", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSelfCAChainVerifiesForEverySAN(t *testing.T) {
	now := time.Now()
	dir := filepath.Join(t.TempDir(), "selfca")
	ca := newTestCA(t, dir, []string{"tincan.lan", "192.168.1.10", "fd00::1"}, now)

	caCert := readCert(t, filepath.Join(dir, caCertFile))
	if !caCert.IsCA || caCert.MaxPathLen != 0 || !caCert.MaxPathLenZero {
		t.Errorf("CA constraints: IsCA=%v MaxPathLen=%d zero=%v", caCert.IsCA, caCert.MaxPathLen, caCert.MaxPathLenZero)
	}
	if caCert.Subject.CommonName != "tin-can-phone local CA testhost" {
		t.Errorf("CA CN %q", caCert.Subject.CommonName)
	}
	if d := caCert.NotAfter.Sub(now); d < 9*365*24*time.Hour {
		t.Errorf("CA validity too short: %v", d)
	}

	srv := readCert(t, filepath.Join(dir, serverCertFile))
	if d := srv.NotAfter.Sub(now); d > serverValidity || d < serverValidity-time.Minute {
		t.Errorf("server validity %v, want %v", d, serverValidity)
	}
	if len(srv.ExtKeyUsage) != 1 || srv.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("EKU %v", srv.ExtKeyUsage)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	for _, name := range []string{"tincan.lan", "192.168.1.10", "fd00::1", "localhost", "127.0.0.1"} {
		if _, err := srv.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: now}); err != nil {
			t.Errorf("verify %s: %v", name, err)
		}
	}
	if _, err := srv.Verify(x509.VerifyOptions{DNSName: "other.lan", Roots: roots, CurrentTime: now}); err == nil {
		t.Error("verified for a name not in SANs")
	}

	// GetCertificate serves the same certificate as on disk.
	tc, _ := ca.GetCertificate(nil)
	if !bytes.Equal(tc.Certificate[0], srv.Raw) {
		t.Error("served certificate differs from server.crt")
	}
}

func TestSelfCAFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "selfca")
	newTestCA(t, dir, nil, time.Now())
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir perm %v", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 4 {
		t.Errorf("want 4 files, got %d (temp files left?)", len(entries))
	}
	for _, f := range []string{caCertFile, caKeyFile, serverCertFile, serverKeyFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s perm %v", f, st.Mode().Perm())
		}
	}
}

func TestSelfCARestartReuses(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	first := newTestCA(t, dir, []string{"tincan.lan"}, now)
	srv1 := readCert(t, filepath.Join(dir, serverCertFile))

	second := newTestCA(t, dir, []string{"tincan.lan"}, now.Add(24*time.Hour))
	srv2 := readCert(t, filepath.Join(dir, serverCertFile))

	if !bytes.Equal(first.CACertDER(), second.CACertDER()) {
		t.Error("CA was regenerated on restart")
	}
	if !bytes.Equal(srv1.Raw, srv2.Raw) {
		t.Error("server certificate was re-issued without reason")
	}
}

func TestSelfCAReissueNearExpiry(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	first := newTestCA(t, dir, []string{"tincan.lan"}, now)
	srv1 := readCert(t, filepath.Join(dir, serverCertFile))

	later := srv1.NotAfter.Add(-29 * 24 * time.Hour) // less than 30 days left
	second := newTestCA(t, dir, []string{"tincan.lan"}, later)
	srv2 := readCert(t, filepath.Join(dir, serverCertFile))

	if !bytes.Equal(first.CACertDER(), second.CACertDER()) {
		t.Fatal("CA changed on server re-issue")
	}
	if bytes.Equal(srv1.Raw, srv2.Raw) {
		t.Fatal("server certificate not re-issued near expiry")
	}
	if !srv2.NotAfter.After(srv1.NotAfter) {
		t.Errorf("new NotAfter %v not after old %v", srv2.NotAfter, srv1.NotAfter)
	}
	assertSignedBy(t, srv2, second, later)

	// 31 days left: no re-issue.
	dir2 := t.TempDir()
	newTestCA(t, dir2, nil, now)
	a := readCert(t, filepath.Join(dir2, serverCertFile))
	newTestCA(t, dir2, nil, a.NotAfter.Add(-31*24*time.Hour))
	b := readCert(t, filepath.Join(dir2, serverCertFile))
	if !bytes.Equal(a.Raw, b.Raw) {
		t.Error("re-issued with 31 days left")
	}
}

func TestSelfCAReissueOnSANChange(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	first := newTestCA(t, dir, []string{"tincan.lan"}, now)
	srv1 := readCert(t, filepath.Join(dir, serverCertFile))

	second := newTestCA(t, dir, []string{"tincan.lan", "10.0.0.5"}, now)
	srv2 := readCert(t, filepath.Join(dir, serverCertFile))

	if !bytes.Equal(first.CACertDER(), second.CACertDER()) {
		t.Fatal("CA changed on SAN change")
	}
	if bytes.Equal(srv1.Raw, srv2.Raw) {
		t.Fatal("server certificate not re-issued after SAN change")
	}
	assertSignedBy(t, srv2, second, now)
	roots := x509.NewCertPool()
	roots.AddCert(second.caCert)
	if _, err := srv2.Verify(x509.VerifyOptions{DNSName: "10.0.0.5", Roots: roots, CurrentTime: now}); err != nil {
		t.Errorf("new SAN not valid: %v", err)
	}

	// Same set in a different order / with duplicates: no re-issue.
	newTestCA(t, dir, []string{"10.0.0.5", "TINCAN.lan", "tincan.lan", "localhost"}, now)
	srv3 := readCert(t, filepath.Join(dir, serverCertFile))
	if !bytes.Equal(srv2.Raw, srv3.Raw) {
		t.Error("re-issued although SAN set is unchanged")
	}
}

func TestSelfCARefusesCertWithoutKey(t *testing.T) {
	dir := t.TempDir()
	newTestCA(t, dir, nil, time.Now())
	if err := os.Remove(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatal(err)
	}
	_, err := openSelfCA(selfCAOptions{Dir: dir, Permitted: testPermitted(t, defaultPermitted...)})
	if err == nil {
		t.Fatal("expected error when CA key is missing")
	}
}

func TestSelfCAFixesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	newTestCA(t, dir, nil, time.Now())
	key := filepath.Join(dir, caKeyFile)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	newTestCA(t, dir, nil, time.Now())
	st, _ := os.Stat(key)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("perm %v", st.Mode().Perm())
	}
}

func assertSignedBy(t *testing.T, leaf *x509.Certificate, ca *selfCA, at time.Time) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at}); err != nil {
		t.Errorf("not signed by CA: %v", err)
	}
}
