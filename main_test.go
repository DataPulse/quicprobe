package main

import (
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

// These tests exercise the probe function directly (unit) and the binary (integration).
// They require network access to reach public hosts.

func TestProbe_GoogleSupportsQUIC(t *testing.T) {
	r := probe("google.com", 5*time.Second)
	if !r.Supported {
		t.Fatalf("expected google.com to support QUIC, got error: %s", r.Error)
	}
	if r.ALPN != "h3" {
		t.Errorf("expected ALPN h3, got %q", r.ALPN)
	}
	if r.TLSVersion != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %q", r.TLSVersion)
	}
	if r.ServerAddr == "" {
		t.Error("expected non-empty server address")
	}
	if r.HandshakeMs <= 0 {
		t.Errorf("expected positive handshake time, got %d", r.HandshakeMs)
	}
}

func TestProbe_CloudflareFrontedDomain(t *testing.T) {
	r := probe("anthropic.com", 5*time.Second)
	if !r.Supported {
		t.Fatalf("expected anthropic.com (Cloudflare) to support QUIC, got error: %s", r.Error)
	}
	if r.ALPN != "h3" {
		t.Errorf("expected ALPN h3, got %q", r.ALPN)
	}
}

func TestProbe_NonQUICHost(t *testing.T) {
	r := probe("example.com", 5*time.Second)
	if r.Supported {
		t.Error("expected example.com to NOT support QUIC")
	}
	if r.Error == "" {
		t.Error("expected error message for non-QUIC host")
	}
}

func TestProbe_NXDomain(t *testing.T) {
	r := probe("nxdomain-quictest.invalid", 3*time.Second)
	if r.Supported {
		t.Error("expected NXDOMAIN to fail")
	}
	if r.Error == "" {
		t.Error("expected error for NXDOMAIN")
	}
}

func TestProbe_Timeout(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — black-hole, should timeout
	start := time.Now()
	r := probe("192.0.2.1", 1*time.Second)
	elapsed := time.Since(start)

	if r.Supported {
		t.Error("expected timeout for black-hole IP")
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("probe returned too fast (%v), expected ~1s timeout", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("probe took too long (%v), timeout should be ~1s", elapsed)
	}
}

func TestProbe_JSONOutputFormat(t *testing.T) {
	r := probe("google.com", 5*time.Second)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}

	// Verify it round-trips cleanly
	var parsed result
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Supported != r.Supported {
		t.Error("round-trip mismatch on Supported")
	}
	if parsed.ALPN != r.ALPN {
		t.Error("round-trip mismatch on ALPN")
	}
}

func TestProbe_DifferentHostsDifferentAddresses(t *testing.T) {
	r1 := probe("google.com", 5*time.Second)
	r2 := probe("cloudflare.com", 5*time.Second)
	if !r1.Supported || !r2.Supported {
		t.Skip("both hosts must support QUIC for this test")
	}
	if r1.ServerAddr == r2.ServerAddr {
		t.Errorf("expected different server addresses, both got %s", r1.ServerAddr)
	}
}

// Integration test: runs the compiled binary and checks JSON output
func TestBinary_JSONOutput(t *testing.T) {
	// Build the binary first
	cmd := exec.Command("go", "build", "-o", "quicprobe_test_bin", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	defer func() {
		_ = exec.Command("rm", "quicprobe_test_bin").Run()
	}()

	cmd = exec.Command("./quicprobe_test_bin", "google.com", "5")
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("binary execution failed: %v", err)
	}

	var r result
	if err := json.Unmarshal(stdout, &r); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nraw: %s", err, stdout)
	}
	if !r.Supported {
		t.Error("expected google.com to support QUIC via binary")
	}
	if r.ALPN != "h3" {
		t.Errorf("expected ALPN h3 via binary, got %q", r.ALPN)
	}
}

func TestBinary_NoArgs(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "quicprobe_test_bin", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	defer func() {
		_ = exec.Command("rm", "quicprobe_test_bin").Run()
	}()

	cmd = exec.Command("./quicprobe_test_bin")
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("binary should exit 0 even with no args: %v", err)
	}

	var r result
	if err := json.Unmarshal(stdout, &r); err != nil {
		t.Fatalf("failed to parse JSON: %v\nraw: %s", err, stdout)
	}
	if r.Supported {
		t.Error("expected supported=false with no args")
	}
	if r.Error == "" {
		t.Error("expected usage error message")
	}
}
