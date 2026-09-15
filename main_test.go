package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// These tests exercise parseArgs and probe directly (unit) and the binary
// (integration). Local quic-go / TLS servers cover the protocol paths
// without network access; tests against public hosts are skipped with
// -short.

func hostOpts(host string, timeout time.Duration) options {
	return options{Host: host, Port: quicPort, Timeout: timeout}
}

func requireNetwork(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
}

// lookupFirst resolves host to its first address of the given family
// ("ip4"/"ip6") or skips the test.
func lookupFirst(t *testing.T, network, host string) netip.Addr {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil || len(addrs) == 0 {
		t.Skipf("cannot resolve %s over %s: %v", host, network, err)
	}
	return addrs[0].Unmap()
}

// selfSignedCert returns a throwaway certificate for local test servers.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startLocalQUIC runs a real quic-go server on 127.0.0.1 offering the
// given ALPNs and returns its address and port.
func startLocalQUIC(t *testing.T, nextProtos []string) (netip.Addr, int) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, NextProtos: nextProtos}
	ln, err := quic.Listen(udpConn, tlsConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			_ = conn.CloseWithError(0, "bye")
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = udpConn.Close()
	})
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	return netip.MustParseAddr("127.0.0.1"), port
}

// startLocalHTTPS runs an HTTP/2-capable TLS server on 127.0.0.1 with the
// given handler and returns its address and port.
func startLocalHTTPS(t *testing.T, handler http.HandlerFunc) (*httptest.Server, netip.Addr, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	return srv, ap.Addr(), int(ap.Port())
}

// --- parseArgs -------------------------------------------------------------

func TestParseArgs_Positional(t *testing.T) {
	opts, err := parseArgs([]string{"example.com", "7"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != "example.com" || opts.Timeout != 7*time.Second || opts.Family != familyAny || opts.IP.IsValid() {
		t.Errorf("unexpected options: %+v", opts)
	}
	if opts.Port != quicPort || opts.AltSvc {
		t.Errorf("expected default port and no altsvc, got %+v", opts)
	}
}

func TestParseArgs_DefaultTimeout(t *testing.T) {
	opts, err := parseArgs([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Timeout != defaultTimeoutSec*time.Second {
		t.Errorf("expected default timeout, got %v", opts.Timeout)
	}
}

func TestParseArgs_BadPositionalTimeoutIgnored(t *testing.T) {
	opts, err := parseArgs([]string{"example.com", "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Timeout != defaultTimeoutSec*time.Second {
		t.Errorf("bad positional timeout should fall back to default, got %v", opts.Timeout)
	}
}

func TestParseArgs_FlagTimeoutWins(t *testing.T) {
	opts, err := parseArgs([]string{"-t", "3", "example.com", "9"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Timeout != 3*time.Second {
		t.Errorf("-t should override positional timeout, got %v", opts.Timeout)
	}
}

func TestParseArgs_Families(t *testing.T) {
	cases := []struct {
		args   []string
		family string
	}{
		{[]string{"-4", "example.com"}, familyIPv4},
		{[]string{"-6", "example.com"}, familyIPv6},
		{[]string{"example.com"}, familyAny},
	}
	for _, c := range cases {
		opts, err := parseArgs(c.args)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if opts.Family != c.family {
			t.Errorf("%v: family %q, want %q", c.args, opts.Family, c.family)
		}
	}
}

func TestParseArgs_IP(t *testing.T) {
	opts, err := parseArgs([]string{"-ip", "104.18.32.7", "anthropic.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.IP.String() != "104.18.32.7" || opts.Host != "anthropic.com" {
		t.Errorf("unexpected options: %+v", opts)
	}
	opts, err = parseArgs([]string{"-6", "-ip", "2606:4700::6812:2007", "anthropic.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.IP.Is6() {
		t.Errorf("expected IPv6 target, got %v", opts.IP)
	}
}

func TestParseArgs_IPv4MappedIsUnmapped(t *testing.T) {
	opts, err := parseArgs([]string{"-4", "-ip", "::ffff:1.2.3.4", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.IP.Is4() || opts.IP.String() != "1.2.3.4" {
		t.Errorf("expected unmapped 1.2.3.4, got %v", opts.IP)
	}
}

func TestParseArgs_PortAndAltSvc(t *testing.T) {
	opts, err := parseArgs([]string{"-p", "8443", "-altsvc", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Port != 8443 || !opts.AltSvc {
		t.Errorf("expected port 8443 and altsvc, got %+v", opts)
	}
}

func TestParseArgs_Errors(t *testing.T) {
	cases := [][]string{
		{},
		{""},
		{"-4", "-6", "example.com"},
		{"-ip", "not-an-ip", "example.com"},
		{"-4", "-ip", "2001:db8::1", "example.com"},
		{"-6", "-ip", "192.0.2.1", "example.com"},
		{"-bogus", "example.com"},
		{"a", "b", "c"},
		{"-p", "0", "example.com"},
		{"-p", "70000", "example.com"},
		{"-p", "abc", "example.com"},
	}
	for _, args := range cases {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
}

// --- classifyError / describeAlert -----------------------------------------

func TestClassifyError(t *testing.T) {
	// Captured verbatim from a CloudFront distribution with HTTP/3 disabled.
	cloudfront := &quic.TransportError{Remote: true, ErrorCode: 0x128, ErrorMessage: "tls: handshake failure"}
	cases := []struct {
		name      string
		err       error
		reason    string
		alert     string
		alertCode int
	}{
		{"nil", nil, "", "", 0},
		{"cloudfront handshake failure", cloudfront, reasonTLSRejected, "handshake failure", 40},
		{"wrapped cloudfront", fmt.Errorf("dial: %w", cloudfront), reasonTLSRejected, "handshake failure", 40},
		{"no application protocol", &quic.TransportError{Remote: true, ErrorCode: 0x178}, reasonTLSRejected, "no application protocol", 120},
		{"local crypto error", &quic.TransportError{ErrorCode: 0x150}, reasonTLSRejected, "internal error", 80},
		{"context deadline", context.DeadlineExceeded, reasonTimeout, "", 0},
		{"wrapped deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), reasonTimeout, "", 0},
		{"handshake timeout", &quic.HandshakeTimeoutError{}, reasonTimeout, "", 0},
		{"idle timeout", &quic.IdleTimeoutError{}, reasonTimeout, "", 0},
		{"version negotiation", &quic.VersionNegotiationError{}, reasonVersionNegotiation, "", 0},
		{"stateless reset", &quic.StatelessResetError{}, reasonStatelessReset, "", 0},
		{"connection refused", &quic.TransportError{Remote: true, ErrorCode: quic.ConnectionRefused}, reasonTransportError, "", 0},
		{"application error", &quic.ApplicationError{Remote: true, ErrorCode: 1}, reasonApplicationError, "", 0},
		{"plain error", errors.New("boom"), reasonOther, "", 0},
	}
	for _, c := range cases {
		reason, alert, code := classifyError(c.err)
		if reason != c.reason || alert != c.alert || code != c.alertCode {
			t.Errorf("%s: got (%q, %q, %d), want (%q, %q, %d)", c.name, reason, alert, code, c.reason, c.alert, c.alertCode)
		}
	}
}

func TestDescribeAlert(t *testing.T) {
	cases := []struct {
		code quic.TransportErrorCode
		name string
		num  int
	}{
		{0x128, "handshake failure", 40},
		{0x178, "no application protocol", 120},
		{0x170, "unrecognized name", 112},
		{0x1fa, "alert(250)", 250},
		{quic.ConnectionRefused, "", 0},
	}
	for _, c := range cases {
		name, num := describeAlert(c.code)
		if name != c.name || num != c.num {
			t.Errorf("%#x: got (%q, %d), want (%q, %d)", uint64(c.code), name, num, c.name, c.num)
		}
	}
}

func TestHasH3Token(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{`h3=":443"; ma=86400`, true},                               // CloudFront
		{`h3=":443"; ma=86400, h3-29=":443"; ma=86400`, true},       // Cloudflare style
		{`h3-29=":443"; ma=2592000,h3-27=":443"; ma=2592000`, true}, // drafts only
		{`h2=":443", h3=":443"`, true},
		{`h2=":443"`, false},
		{`clear`, false},
		{``, false},
		{`h30=":443"`, false},
	}
	for _, c := range cases {
		if got := hasH3Token(c.header); got != c.want {
			t.Errorf("%q: got %v, want %v", c.header, got, c.want)
		}
	}
}

// --- probe: unit-level failures without network -----------------------------

func TestProbe_UnresolvableHost(t *testing.T) {
	r := probe(hostOpts("nxdomain-quictest.invalid", 3*time.Second))
	if r.Supported || r.Error == "" {
		t.Errorf("expected failure for .invalid host, got %+v", r)
	}
	if r.TargetIP != "" {
		t.Errorf("no target IP expected when resolution fails, got %q", r.TargetIP)
	}
	if r.Reason != reasonResolveFailed {
		t.Errorf("reason %q, want %q", r.Reason, reasonResolveFailed)
	}
}

func TestProbe_Timeout(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — black-hole, should timeout
	start := time.Now()
	r := probe(options{Host: "example.com", IP: netip.MustParseAddr("192.0.2.1"), Port: quicPort, Timeout: time.Second})
	elapsed := time.Since(start)

	if r.Supported {
		t.Error("expected timeout for black-hole IP")
	}
	if r.Family != familyIPv4 || r.TargetIP != "192.0.2.1" {
		t.Errorf("expected ipv4/192.0.2.1 in result, got %+v", r)
	}
	if r.Reason != reasonTimeout {
		t.Errorf("reason %q, want %q", r.Reason, reasonTimeout)
	}
	if r.TLSAlert != "" || r.TLSAlertCode != 0 || r.AltSvc != nil {
		t.Errorf("unexpected TLS/alt-svc fields on timeout: %+v", r)
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("probe returned too fast (%v), expected ~1s timeout", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("probe took too long (%v), timeout should be ~1s", elapsed)
	}
}

func TestProbe_LegacyIPLiteralHost(t *testing.T) {
	// Passing an IP as the hostname keeps working (no SNI, so a black-hole
	// address is used to avoid depending on any server's SNI policy).
	r := probe(hostOpts("192.0.2.2", time.Second))
	if r.TargetIP != "192.0.2.2" || r.Family != familyIPv4 {
		t.Errorf("expected literal host to be dialed directly, got %+v", r)
	}
}

// --- probe: local quic-go servers --------------------------------------------

func TestProbe_LocalServerSupportsH3(t *testing.T) {
	ip, port := startLocalQUIC(t, []string{"h3"})
	r := probe(options{Host: "localhost", IP: ip, Port: port, Timeout: 5 * time.Second})
	if !r.Supported {
		t.Fatalf("expected local h3 server to be supported, got %+v", r)
	}
	if r.ALPN != "h3" || r.TLSVersion != "TLS 1.3" || r.Reason != "" || r.Error != "" {
		t.Errorf("unexpected result: %+v", r)
	}
	if r.ServerAddr != fmt.Sprintf("127.0.0.1:%d", port) || r.TargetIP != "127.0.0.1" || r.Family != familyIPv4 {
		t.Errorf("unexpected address fields: %+v", r)
	}
}

func TestProbe_LocalServerRejectsALPN(t *testing.T) {
	// A QUIC server that does not offer h3 refuses the handshake with TLS
	// alert 120 — the same code path CloudFront takes (with alert 40) when
	// HTTP/3 is disabled on a distribution.
	ip, port := startLocalQUIC(t, []string{"not-h3"})
	r := probe(options{Host: "localhost", IP: ip, Port: port, Timeout: 5 * time.Second})
	if r.Supported {
		t.Fatalf("expected rejection, got %+v", r)
	}
	if r.Reason != reasonTLSRejected {
		t.Errorf("reason %q, want %q (error: %s)", r.Reason, reasonTLSRejected, r.Error)
	}
	if r.TLSAlertCode != 120 || r.TLSAlert != "no application protocol" {
		t.Errorf("expected alert 120 / no application protocol, got %d / %q", r.TLSAlertCode, r.TLSAlert)
	}
	if !strings.Contains(r.Error, "CRYPTO_ERROR 0x178") {
		t.Errorf("error should mention CRYPTO_ERROR 0x178, got %q", r.Error)
	}
}

// --- probe: Alt-Svc cross-check -----------------------------------------------

func TestCheckAltSvc_H3Advertised(t *testing.T) {
	_, ip, port := startLocalHTTPS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
	})
	got := checkAltSvc(options{Host: "localhost", Port: port, Timeout: 5 * time.Second}, ip)
	if got.Error != "" || !got.H3 || got.Status != http.StatusOK || got.ALPN != "h2" {
		t.Errorf("unexpected alt-svc result: %+v", got)
	}
	if got.Header != `h3=":443"; ma=86400` {
		t.Errorf("header %q not preserved", got.Header)
	}
}

func TestCheckAltSvc_NoHeader(t *testing.T) {
	_, ip, port := startLocalHTTPS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	got := checkAltSvc(options{Host: "localhost", Port: port, Timeout: 5 * time.Second}, ip)
	if got.Error != "" || got.H3 || got.Header != "" || got.Status != http.StatusOK {
		t.Errorf("unexpected alt-svc result: %+v", got)
	}
}

func TestCheckAltSvc_RedirectNotFollowed(t *testing.T) {
	// datapulse.global's apex answers 301 → www; the Alt-Svc on that
	// response is what matters, and we must not chase the Location.
	var hits int
	_, ip, port := startLocalHTTPS(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Set("Location", "https://www.example.invalid/")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	got := checkAltSvc(options{Host: "localhost", Port: port, Timeout: 5 * time.Second}, ip)
	if got.Error != "" || !got.H3 || got.Status != http.StatusMovedPermanently {
		t.Errorf("unexpected alt-svc result: %+v", got)
	}
	if hits != 1 {
		t.Errorf("expected exactly one request, got %d", hits)
	}
}

func TestCheckAltSvc_UsesSNI(t *testing.T) {
	var sni string
	_, ip, port := startLocalHTTPS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		w.WriteHeader(http.StatusOK)
	})
	checkAltSvc(options{Host: "probe.example", Port: port, Timeout: 5 * time.Second}, ip)
	if sni != "probe.example" {
		t.Errorf("SNI %q, want probe.example", sni)
	}
}

func TestCheckAltSvc_ServerDown(t *testing.T) {
	srv, ip, port := startLocalHTTPS(t, func(w http.ResponseWriter, r *http.Request) {})
	srv.Close()
	got := checkAltSvc(options{Host: "localhost", Port: port, Timeout: 2 * time.Second}, ip)
	if got.Error == "" || got.H3 || got.Status != 0 {
		t.Errorf("expected error for closed server, got %+v", got)
	}
}

func TestProbe_AltSvcAttachedOnQUICFailure(t *testing.T) {
	// QUIC times out (black-hole target) but Alt-Svc is still reported when
	// requested, and omitted when not.
	r := probe(options{Host: "example.com", IP: netip.MustParseAddr("192.0.2.1"), Port: quicPort, Timeout: time.Second, AltSvc: true})
	if r.Reason != reasonTimeout || r.AltSvc == nil || r.AltSvc.Error == "" {
		t.Errorf("expected timeout with failed alt-svc check attached, got %+v", r)
	}
	r = probe(options{Host: "example.com", IP: netip.MustParseAddr("192.0.2.1"), Port: quicPort, Timeout: time.Second})
	if r.AltSvc != nil {
		t.Errorf("alt_svc must be absent without -altsvc, got %+v", r.AltSvc)
	}
}

// --- probe: network ----------------------------------------------------------

func TestProbe_GoogleSupportsQUIC(t *testing.T) {
	requireNetwork(t)
	r := probe(hostOpts("google.com", 5*time.Second))
	if !r.Supported {
		t.Fatalf("expected google.com to support QUIC, got error: %s", r.Error)
	}
	if r.ALPN != "h3" {
		t.Errorf("expected ALPN h3, got %q", r.ALPN)
	}
	if r.TLSVersion != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %q", r.TLSVersion)
	}
	if r.ServerAddr == "" || r.TargetIP == "" || r.Family == "" {
		t.Errorf("expected address, target and family, got %+v", r)
	}
	if r.HandshakeMs <= 0 {
		t.Errorf("expected positive handshake time, got %d", r.HandshakeMs)
	}
	if r.Reason != "" {
		t.Errorf("reason must be empty on success, got %q", r.Reason)
	}
}

func TestProbe_ForceIPv4(t *testing.T) {
	requireNetwork(t)
	r := probe(options{Host: "google.com", Family: familyIPv4, Port: quicPort, Timeout: 5 * time.Second})
	if !r.Supported {
		t.Fatalf("expected IPv4 QUIC to google.com, got: %s", r.Error)
	}
	if r.Family != familyIPv4 || !netip.MustParseAddr(r.TargetIP).Is4() {
		t.Errorf("expected IPv4 target, got %+v", r)
	}
	if strings.HasPrefix(r.ServerAddr, "[") {
		t.Errorf("server address should be IPv4, got %s", r.ServerAddr)
	}
}

func TestProbe_ForceIPv6(t *testing.T) {
	requireNetwork(t)
	lookupFirst(t, "ip6", "google.com")
	r := probe(options{Host: "google.com", Family: familyIPv6, Port: quicPort, Timeout: 5 * time.Second})
	if !r.Supported {
		t.Skipf("IPv6 QUIC to google.com failed (no IPv6 route?): %s", r.Error)
	}
	if r.Family != familyIPv6 || !netip.MustParseAddr(r.TargetIP).Is6() {
		t.Errorf("expected IPv6 target, got %+v", r)
	}
	if !strings.HasPrefix(r.ServerAddr, "[") {
		t.Errorf("server address should be IPv6, got %s", r.ServerAddr)
	}
}

func TestProbe_ExplicitIPKeepsSNI(t *testing.T) {
	// Cloudflare-fronted hosts refuse handshakes without SNI, so success here
	// proves the hostname is sent as ServerName while dialing the literal.
	requireNetwork(t)
	ip := lookupFirst(t, "ip4", "anthropic.com")
	r := probe(options{Host: "anthropic.com", IP: ip, Port: quicPort, Timeout: 5 * time.Second})
	if !r.Supported {
		t.Fatalf("expected anthropic.com via -ip %s to support QUIC, got error: %s", ip, r.Error)
	}
	if r.TargetIP != ip.String() {
		t.Errorf("target_ip %q, want %q", r.TargetIP, ip)
	}
	if !strings.HasPrefix(r.ServerAddr, ip.String()+":") {
		t.Errorf("server_addr %q should be the dialed IP %s", r.ServerAddr, ip)
	}
}

func TestProbe_NonQUICHost(t *testing.T) {
	requireNetwork(t)
	r := probe(hostOpts("example.com", 5*time.Second))
	if r.Supported {
		t.Error("expected example.com to NOT support QUIC")
	}
	if r.Error == "" || r.Reason == "" {
		t.Errorf("expected error message and reason for non-QUIC host, got %+v", r)
	}
}

func TestProbe_AltSvcCloudFrontH3(t *testing.T) {
	// d1.awsstatic.com is a CloudFront distribution with HTTP/3 enabled: the
	// QUIC handshake succeeds and TCP advertises h3 via Alt-Svc. CloudFront
	// omits the Alt-Svc header on a small fraction of responses (observed
	// with curl too), so the header check is retried a few times.
	requireNetwork(t)
	opts := options{Host: "d1.awsstatic.com", Port: quicPort, Timeout: 5 * time.Second, AltSvc: true}
	var last result
	for attempt := 0; attempt < 4; attempt++ {
		last = probe(opts)
		if !last.Supported {
			t.Fatalf("expected d1.awsstatic.com to support QUIC, got: %s", last.Error)
		}
		if last.AltSvc == nil || last.AltSvc.Error != "" || last.AltSvc.ALPN == "" || last.AltSvc.Status != http.StatusOK {
			t.Fatalf("alt-svc check itself failed: %+v", last.AltSvc)
		}
		if last.AltSvc.H3 {
			return
		}
	}
	t.Errorf("Alt-Svc never advertised h3 in 4 attempts, last: %+v", last.AltSvc)
}

func TestProbe_JSONOutputFormat(t *testing.T) {
	r := result{Supported: true, ALPN: "h3", Family: familyIPv4, TargetIP: "1.2.3.4", HandshakeMs: 12}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}
	var parsed result
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed != r {
		t.Errorf("round-trip mismatch: %+v vs %+v", parsed, r)
	}
	for _, key := range []string{`"error"`, `"reason"`, `"tls_alert"`, `"tls_alert_code"`, `"alt_svc"`} {
		if strings.Contains(string(b), key) {
			t.Errorf("empty %s should be omitted: %s", key, b)
		}
	}
}

func TestProbe_JSONFailureFormat(t *testing.T) {
	r := result{
		Family: familyIPv6, TargetIP: "2600:9000::1", HandshakeMs: 46,
		Reason: reasonTLSRejected, TLSAlert: "handshake failure", TLSAlertCode: 40,
		AltSvc: &altSvcResult{H3: false, ALPN: "h2", Status: 301},
		Error:  "CRYPTO_ERROR 0x128 (remote): tls: handshake failure",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["reason"] != reasonTLSRejected || m["tls_alert"] != "handshake failure" || m["tls_alert_code"] != float64(40) {
		t.Errorf("unexpected failure JSON: %s", b)
	}
	alt, ok := m["alt_svc"].(map[string]any)
	if !ok || alt["h3"] != false || alt["alpn"] != "h2" || alt["status"] != float64(301) {
		t.Errorf("unexpected alt_svc JSON: %s", b)
	}
	if _, present := alt["header"]; present {
		t.Errorf("empty alt_svc.header should be omitted: %s", b)
	}
}

// --- binary ------------------------------------------------------------------

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "quicprobe_test_bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func runBinaryRaw(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	stdout, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("binary execution failed: %v", err)
	}
	return stdout
}

func runBinary(t *testing.T, bin string, args ...string) result {
	t.Helper()
	stdout := runBinaryRaw(t, bin, args...)
	var r result
	if err := json.Unmarshal(stdout, &r); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nraw: %s", err, stdout)
	}
	return r
}

func TestBinary_JSONOutput(t *testing.T) {
	requireNetwork(t)
	bin := buildBinary(t)
	r := runBinary(t, bin, "google.com", "5")
	if !r.Supported {
		t.Error("expected google.com to support QUIC via binary")
	}
	if r.ALPN != "h3" {
		t.Errorf("expected ALPN h3 via binary, got %q", r.ALPN)
	}
}

func TestBinary_FlagsIPAndFamily(t *testing.T) {
	requireNetwork(t)
	ip := lookupFirst(t, "ip4", "google.com")
	bin := buildBinary(t)
	r := runBinary(t, bin, "-4", "-ip", ip.String(), "-t", "5", "google.com")
	if !r.Supported || r.TargetIP != ip.String() || r.Family != familyIPv4 {
		t.Errorf("unexpected binary result: %+v", r)
	}
}

func TestBinary_AltSvcFlag(t *testing.T) {
	requireNetwork(t)
	bin := buildBinary(t)
	with := runBinaryRaw(t, bin, "-altsvc", "-t", "5", "d1.awsstatic.com")
	if !strings.Contains(string(with), `"alt_svc":{`) {
		t.Errorf("expected alt_svc object with -altsvc: %s", with)
	}
	without := runBinaryRaw(t, bin, "-t", "5", "d1.awsstatic.com")
	if strings.Contains(string(without), `"alt_svc"`) {
		t.Errorf("alt_svc must be absent without -altsvc: %s", without)
	}
}

func TestBinary_LocalPortAndReason(t *testing.T) {
	ip, port := startLocalQUIC(t, []string{"not-h3"})
	bin := buildBinary(t)
	r := runBinary(t, bin, "-ip", ip.String(), "-p", fmt.Sprint(port), "-t", "5", "localhost")
	if r.Supported || r.Reason != reasonTLSRejected || r.TLSAlertCode != 120 {
		t.Errorf("unexpected binary result: %+v", r)
	}
}

func TestBinary_NoArgs(t *testing.T) {
	bin := buildBinary(t)
	stdout, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatalf("binary should exit 0 even with no args: %v", err)
	}
	var r result
	if err := json.Unmarshal(stdout, &r); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, stdout)
	}
	if r.Supported || !strings.HasPrefix(r.Error, "usage:") || r.Reason != reasonInvalidArgs {
		t.Errorf("expected usage error, got %+v", r)
	}
}

func TestBinary_BadFlagStillExitsZero(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "-ip", "garbage", "example.com")
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("binary should exit 0 on bad flags: %v", err)
	}
	var r result
	if err := json.Unmarshal(stdout, &r); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, stdout)
	}
	if r.Supported || !strings.Contains(r.Error, "invalid -ip") || r.Reason != reasonInvalidArgs {
		t.Errorf("expected invalid -ip error, got %+v", r)
	}
	if _, statErr := os.Stat(bin); statErr != nil {
		t.Fatalf("binary vanished: %v", statErr)
	}
}
