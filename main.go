// quicprobe — Lightweight QUIC/HTTP3 support probe.
//
// Attempts a QUIC handshake to hostname:443 with ALPN "h3" and reports
// whether the server supports QUIC, which ALPN was negotiated, TLS version,
// and server address. Outputs JSON to stdout; exit code is always 0.
//
// Usage: quicprobe <hostname> [timeout_seconds]
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

func init() {
	// Suppress quic-go's UDP buffer size warning on stderr.
	log.SetOutput(io.Discard)
}

const defaultTimeoutSec = 5

type result struct {
	Supported   bool   `json:"supported"`
	ALPN        string `json:"alpn,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	ServerAddr  string `json:"server_addr,omitempty"`
	HandshakeMs int64  `json:"handshake_ms"`
	Error       string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		writeResult(result{Error: "usage: quicprobe <hostname> [timeout_seconds]"})
		return
	}

	hostname := os.Args[1]
	timeoutSec := defaultTimeoutSec
	if len(os.Args) >= 3 {
		if v, err := strconv.Atoi(os.Args[2]); err == nil && v > 0 {
			timeoutSec = v
		}
	}

	r := probe(hostname, time.Duration(timeoutSec)*time.Second)
	writeResult(r)
}

func probe(hostname string, timeout time.Duration) result {
	start := time.Now()
	addr := hostname + ":443"

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return result{
			Supported:   false,
			HandshakeMs: elapsed,
			Error:       err.Error(),
		}
	}
	defer conn.CloseWithError(0, "probe complete")

	state := conn.ConnectionState().TLS
	return result{
		Supported:   true,
		ALPN:        state.NegotiatedProtocol,
		TLSVersion:  formatTLSVersion(state.Version),
		ServerAddr:  conn.RemoteAddr().String(),
		HandshakeMs: elapsed,
	}
}

func formatTLSVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func writeResult(r result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "")
	_ = enc.Encode(r)
}
