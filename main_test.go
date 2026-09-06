package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise parseArgs and probe directly (unit) and the binary
// (integration). Network tests require access to public hosts; run with
// -short to skip them.

func hostOpts(host string, timeout time.Duration) options {
	return options{Host: host, Timeout: timeout}
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

// --- parseArgs -------------------------------------------------------------

func TestParseArgs_Positional(t *testing.T) {
	opts, err := parseArgs([]string{"example.com", "7"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != "example.com" || opts.Timeout != 7*time.Second || opts.Family != familyAny || opts.IP.IsValid() {
		t.Errorf("unexpected options: %+v", opts)
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
	}
	for _, args := range cases {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("expected error for %v", args)
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
}

func TestProbe_Timeout(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — black-hole, should timeout
	start := time.Now()
	r := probe(options{Host: "example.com", IP: netip.MustParseAddr("192.0.2.1"), Timeout: time.Second})
	elapsed := time.Since(start)

	if r.Supported {
		t.Error("expected timeout for black-hole IP")
	}
	if r.Family != familyIPv4 || r.TargetIP != "192.0.2.1" {
		t.Errorf("expected ipv4/192.0.2.1 in result, got %+v", r)
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
}

func TestProbe_ForceIPv4(t *testing.T) {
	requireNetwork(t)
	r := probe(options{Host: "google.com", Family: familyIPv4, Timeout: 5 * time.Second})
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
	r := probe(options{Host: "google.com", Family: familyIPv6, Timeout: 5 * time.Second})
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
	r := probe(options{Host: "anthropic.com", IP: ip, Timeout: 5 * time.Second})
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
	if r.Error == "" {
		t.Error("expected error message for non-QUIC host")
	}
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
	if strings.Contains(string(b), `"error"`) {
		t.Errorf("empty error should be omitted: %s", b)
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

func runBinary(t *testing.T, bin string, args ...string) result {
	t.Helper()
	stdout, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("binary execution failed: %v", err)
	}
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
	if r.Supported || !strings.HasPrefix(r.Error, "usage:") {
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
	if r.Supported || !strings.Contains(r.Error, "invalid -ip") {
		t.Errorf("expected invalid -ip error, got %+v", r)
	}
	if _, statErr := os.Stat(bin); statErr != nil {
		t.Fatalf("binary vanished: %v", statErr)
	}
}
