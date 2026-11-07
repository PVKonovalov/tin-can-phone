package tlsmode

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// installCSS is inlined into the install page and allowed by CSP hash, so the
// page needs no other resources (port 80 serves nothing else).
const installCSS = `
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:46rem;margin:0 auto;padding:1rem;color:#1d1d1f;background:#fafafa}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:1.75rem}
code,.fp{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.9em;word-break:break-all}
.fp{display:block;padding:.5rem;background:#eee;border-radius:4px}
.btn{display:inline-block;margin:.25rem .5rem .25rem 0;padding:.5rem 1rem;border-radius:6px;background:#0a62c9;color:#fff;text-decoration:none}
.warn{padding:.75rem;border-left:4px solid #c98a0a;background:#fff6e0}
@media (prefers-color-scheme:dark){body{color:#eee;background:#151515}.fp{background:#262626}.warn{background:#33290f}}
`

var installCSP = func() string {
	sum := sha256.Sum256([]byte(installCSS))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

var installTmpl = template.Must(template.New("install").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install tin-can-phone CA</title>
<style>{{.CSS}}</style>
</head>
<body>
<h1>Trust this tin-can-phone server</h1>
<p>This server uses its own certificate authority (CA). Install and trust the CA
certificate once on each device, then open <a href="{{.HTTPSURL}}">{{.HTTPSURL}}</a>.</p>
<p>
<a class="btn" href="/ca.crt">Download ca.crt</a>
<a class="btn" href="/ca.mobileconfig">iOS / macOS profile</a>
</p>
<p><b>{{.Subject}}</b><br>SHA-256 fingerprint:</p>
<code class="fp">{{.Fingerprint}}</code>
<p>This CA is name-constrained: it can only vouch for names under
{{range $i, $d := .PermDNS}}{{if $i}}, {{end}}<code>{{$d}}</code>{{end}}
and {{if .PermIPs}}addresses in {{range $i, $n := .PermIPs}}{{if $i}}, {{end}}<code>{{$n}}</code>{{end}}{{else}}no IP addresses{{end}}.
Browsers reject anything else it signs.</p>
<p class="warn">This page is served over plain HTTP. Before trusting the certificate,
compare its fingerprint with the one in the server log or one given to you by the
administrator. A trusted CA can vouch for any website, so install only a CA you expect.</p>

<h2>Android</h2>
<ol>
<li>Download <a href="/ca.crt">ca.crt</a>.</li>
<li>Settings → Security &amp; privacy → More security settings → Encryption &amp; credentials →
Install a certificate → <b>CA certificate</b> → Install anyway → pick the downloaded file.
(Menu names vary by vendor; search Settings for “CA certificate”.)</li>
<li>Open the server in Chrome.</li>
</ol>

<h2>iPhone / iPad</h2>
<ol>
<li>Open this page in <b>Safari</b> and tap <a href="/ca.mobileconfig">the profile</a> → Allow.</li>
<li>Settings → Profile Downloaded (or General → VPN &amp; Device Management) → Install.</li>
<li>Settings → General → About → <b>Certificate Trust Settings</b> → enable full trust for
“{{.Subject}}”.</li>
</ol>

<h2>Windows</h2>
<ol>
<li>Download <a href="/ca.crt">ca.crt</a> and open it → Install Certificate → Current User →
“Place all certificates in the following store” → <b>Trusted Root Certification Authorities</b>.</li>
<li>Or in a terminal: <code>certutil -user -addstore Root ca.crt</code></li>
<li>Restart the browser. Chrome and Edge use the Windows store; Firefox normally does too
(otherwise import it under Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities).</li>
</ol>

<h2>macOS</h2>
<ol>
<li>Download <a href="/ca.crt">ca.crt</a> and open it; Keychain Access adds it to the login keychain.</li>
<li>Double-click the certificate → Trust → “When using this certificate”: <b>Always Trust</b>.</li>
<li>Or in a terminal: <code>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt</code></li>
<li>Firefox: Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import.</li>
</ol>

<h2>Linux</h2>
<ol>
<li>Debian/Ubuntu: <code>sudo cp ca.crt /usr/local/share/ca-certificates/tin-can-phone.crt &amp;&amp; sudo update-ca-certificates</code></li>
<li>Fedora/RHEL: <code>sudo cp ca.crt /etc/pki/ca-trust/source/anchors/tin-can-phone.crt &amp;&amp; sudo update-ca-trust</code></li>
<li>Chrome/Chromium (NSS): <code>certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n tin-can-phone -i ca.crt</code></li>
<li>Firefox: Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import.</li>
</ol>
</body>
</html>
`))

// newInstallHandler serves the selfca port-80 endpoints and redirects
// everything else to HTTPS.
func newInstallHandler(ca *selfCA, redirect http.Handler, httpsPort, publicURL string) http.Handler {
	caPEM := ca.CACertPEM()
	profile := mobileConfig(ca)
	permDNS, permIPs := ca.PermittedDescription()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			redirect.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/install":
			base, ok := httpsBase(r.Host, httpsPort, publicURL)
			if !ok {
				http.Error(w, "missing Host header", http.StatusBadRequest)
				return
			}
			httpsURL := "https://" + base + "/"
			var buf bytes.Buffer
			err := installTmpl.Execute(&buf, map[string]any{
				"CSS":         template.CSS(installCSS),
				"HTTPSURL":    httpsURL,
				"Subject":     ca.caCert.Subject.CommonName,
				"Fingerprint": ca.Fingerprint(),
				"PermDNS":     permDNS,
				"PermIPs":     permIPs,
			})
			if err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				return
			}
			h.Set("Content-Security-Policy", installCSP)
			h.Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(buf.Bytes())
		case "/ca.crt":
			h.Set("Content-Type", "application/x-x509-ca-cert")
			h.Set("Content-Disposition", `attachment; filename="tin-can-phone-ca.crt"`)
			_, _ = w.Write(caPEM)
		case "/ca.mobileconfig":
			h.Set("Content-Type", "application/x-apple-aspen-config")
			h.Set("Content-Disposition", `attachment; filename="tin-can-phone-ca.mobileconfig"`)
			_, _ = w.Write(profile)
		default:
			redirect.ServeHTTP(w, r)
		}
	})
}

// mobileConfig builds an unsigned Apple configuration profile containing the
// CA certificate (payload type com.apple.security.root).
func mobileConfig(ca *selfCA) []byte {
	name := ca.caCert.Subject.CommonName
	outerUUID := stableUUID(ca.CACertDER(), "profile")
	innerUUID := stableUUID(ca.CACertDER(), "root")
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>tin-can-phone-ca.crt</string>
			<key>PayloadContent</key>
			<data>`)
	b.WriteString(base64.StdEncoding.EncodeToString(ca.CACertDER()))
	fmt.Fprintf(&b, `</data>
			<key>PayloadDescription</key>
			<string>Adds the tin-can-phone local CA root certificate</string>
			<key>PayloadDisplayName</key>
			<string>%[1]s</string>
			<key>PayloadIdentifier</key>
			<string>com.github.pvkonovalov.tincan.ca.%[2]s</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%[2]s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust the tin-can-phone server certificate authority</string>
	<key>PayloadDisplayName</key>
	<string>%[1]s</string>
	<key>PayloadIdentifier</key>
	<string>com.github.pvkonovalov.tincan.%[3]s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%[3]s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, xmlEscape(name), innerUUID, outerUUID)
	return b.Bytes()
}

// stableUUID derives a UUID (version 5 layout) from the CA so the profile
// identifier stays the same across restarts.
func stableUUID(der []byte, label string) string {
	h := sha256.Sum256(append([]byte(label+":"), der...))
	u := h[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]))
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
