// quicprobe — Lightweight QUIC/HTTP3 support probe.
//
// Attempts a QUIC handshake to hostname:443 with ALPN "h3" and reports
// whether the server supports QUIC, which ALPN was negotiated, TLS version,
// and server address. Outputs JSON to stdout; exit code is always 0.
//
// Usage: quicprobe [-4|-6] [-ip addr] [-t seconds] <hostname> [timeout_seconds]
//
//	-4 / -6   restrict the connection to IPv4 / IPv6
//	-ip addr  dial this IP literal instead of resolving hostname; the
//	          hostname is still sent as the TLS SNI
//	-t secs   handshake timeout (the trailing positional form is kept for
//	          backward compatibility)
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

func init() {
	// Suppress quic-go's UDP buffer size warning on stderr.
	log.SetOutput(io.Discard)
}

const (
	defaultTimeoutSec = 5
	quicPort          = 443
	usageText         = "usage: quicprobe [-4|-6] [-ip addr] [-t seconds] <hostname> [timeout_seconds]"
)

// family names used in options and in the JSON result.
const (
	familyAny  = ""
	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"
)

type result struct {
	Supported   bool   `json:"supported"`
	ALPN        string `json:"alpn,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	ServerAddr  string `json:"server_addr,omitempty"`
	Family      string `json:"family,omitempty"`
	TargetIP    string `json:"target_ip,omitempty"`
	HandshakeMs int64  `json:"handshake_ms"`
	Error       string `json:"error,omitempty"`
}

// options describes one probe.
type options struct {
	Host    string
	IP      netip.Addr // zero value means "resolve Host"
	Family  string     // familyAny, familyIPv4 or familyIPv6
	Timeout time.Duration
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		writeResult(result{Error: err.Error()})
		return
	}
	writeResult(probe(opts))
}

// parseArgs turns command-line arguments into options. It never calls
// os.Exit; every problem is reported as an error so main can emit JSON.
func parseArgs(args []string) (options, error) {
	fs := flag.NewFlagSet("quicprobe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	only4 := fs.Bool("4", false, "IPv4 only")
	only6 := fs.Bool("6", false, "IPv6 only")
	ipText := fs.String("ip", "", "IP literal to dial (hostname used as SNI)")
	timeoutSec := fs.Int("t", 0, "timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return options{}, fmt.Errorf("%s: %w", usageText, err)
	}
	if fs.NArg() < 1 || fs.NArg() > 2 || fs.Arg(0) == "" {
		return options{}, errors.New(usageText)
	}
	opts := options{Host: fs.Arg(0), Timeout: defaultTimeoutSec * time.Second}

	if fs.NArg() == 2 {
		if v, err := strconv.Atoi(fs.Arg(1)); err == nil && v > 0 {
			opts.Timeout = time.Duration(v) * time.Second
		}
	}
	if *timeoutSec > 0 {
		opts.Timeout = time.Duration(*timeoutSec) * time.Second
	}

	family, err := chooseFamily(*only4, *only6)
	if err != nil {
		return options{}, err
	}
	opts.Family = family

	if *ipText != "" {
		ip, err := parseTargetIP(*ipText, family)
		if err != nil {
			return options{}, err
		}
		opts.IP = ip
	}
	return opts, nil
}

func chooseFamily(only4, only6 bool) (string, error) {
	switch {
	case only4 && only6:
		return "", errors.New("-4 and -6 are mutually exclusive")
	case only4:
		return familyIPv4, nil
	case only6:
		return familyIPv6, nil
	default:
		return familyAny, nil
	}
}

// parseTargetIP validates an -ip literal and checks it against a requested
// family. IPv4-mapped IPv6 addresses are unmapped so they dial over IPv4.
func parseTargetIP(text, family string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid -ip %q: %w", text, err)
	}
	ip = ip.Unmap()
	got := familyOf(ip)
	if family != familyAny && family != got {
		return netip.Addr{}, fmt.Errorf("-ip %s is %s but -%s was requested", text, got, family[len(family)-1:])
	}
	return ip, nil
}

func familyOf(ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return familyIPv4
	}
	return familyIPv6
}

func probe(opts options) result {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	target, err := resolveTarget(ctx, opts)
	if err != nil {
		return result{Family: opts.Family, HandshakeMs: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	family := familyOf(target)

	tlsConf := &tls.Config{
		ServerName:         opts.Host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}
	base := result{Family: family, TargetIP: target.String()}

	udpConn, err := net.ListenUDP(udpNetwork(family), nil)
	if err != nil {
		base.HandshakeMs = time.Since(start).Milliseconds()
		base.Error = "listen udp: " + err.Error()
		return base
	}
	defer udpConn.Close()

	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(target, quicPort))
	conn, err := quic.Dial(ctx, udpConn, remote, tlsConf, nil)
	base.HandshakeMs = time.Since(start).Milliseconds()
	if err != nil {
		base.Error = err.Error()
		return base
	}
	defer conn.CloseWithError(0, "probe complete")

	state := conn.ConnectionState().TLS
	base.Supported = true
	base.ALPN = state.NegotiatedProtocol
	base.TLSVersion = formatTLSVersion(state.Version)
	base.ServerAddr = conn.RemoteAddr().String()
	return base
}

// resolveTarget returns the IP to dial: the -ip literal if given, otherwise
// the first address of the requested family for the hostname.
func resolveTarget(ctx context.Context, opts options) (netip.Addr, error) {
	if opts.IP.IsValid() {
		return opts.IP, nil
	}
	if ip, err := netip.ParseAddr(opts.Host); err == nil {
		// Hostname is itself an IP literal (legacy behaviour, no SNI).
		return parseTargetIP(ip.String(), opts.Family)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, lookupNetwork(opts.Family), opts.Host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		a = a.Unmap()
		if opts.Family == familyAny || familyOf(a) == opts.Family {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no %s address for %s", describeFamily(opts.Family), opts.Host)
}

func lookupNetwork(family string) string {
	switch family {
	case familyIPv4:
		return "ip4"
	case familyIPv6:
		return "ip6"
	default:
		return "ip"
	}
}

func udpNetwork(family string) string {
	if family == familyIPv6 {
		return "udp6"
	}
	return "udp4"
}

func describeFamily(family string) string {
	if family == familyAny {
		return "usable"
	}
	return family
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
