// quicprobe — Lightweight QUIC/HTTP3 support probe.
//
// Attempts a QUIC handshake to hostname:port (default 443) with ALPN "h3"
// and reports whether the server supports QUIC, which ALPN was negotiated,
// TLS version, and server address. Outputs JSON to stdout; exit code is
// always 0.
//
// Usage: quicprobe [-4|-6] [-ip addr] [-p port] [-t seconds] [-altsvc] <hostname> [timeout_seconds]
//
//	-4 / -6   restrict the connection to IPv4 / IPv6
//	-ip addr  dial this IP literal instead of resolving hostname; the
//	          hostname is still sent as the TLS SNI
//	-p port   UDP (and, with -altsvc, TCP) port to probe; default 443
//	-t secs   handshake timeout (the trailing positional form is kept for
//	          backward compatibility)
//	-altsvc   after the QUIC attempt, also make a TLS-over-TCP HEAD request
//	          to the same IP and report the Alt-Svc header in "alt_svc".
//	          Alt-Svc is advisory: some CDNs (CloudFront among them) omit
//	          it on a fraction of responses, so "h3": false there is a hint,
//	          not proof; the QUIC handshake result is authoritative.
//
// Every failure carries a "reason" so callers need not parse the free-form
// "error" string:
//
//	invalid_args         bad command line
//	resolve_failed       DNS failure or no address of the requested family
//	listen_failed        could not open a local UDP socket
//	timeout              nothing answered on UDP (no QUIC listener or filtered)
//	tls_rejected         a QUIC endpoint answered but refused the TLS
//	                     handshake ("tls_alert"/"tls_alert_code" say why);
//	                     typically HTTP/3 is not enabled for this hostname
//	version_negotiation  no common QUIC version
//	stateless_reset      peer sent a stateless reset
//	transport_error      other QUIC transport error
//	application_error    peer closed with an application error
//	other                anything else
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
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
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
	usageText         = "usage: quicprobe [-4|-6] [-ip addr] [-p port] [-t seconds] [-altsvc] <hostname> [timeout_seconds]"
)

// family names used in options and in the JSON result.
const (
	familyAny  = ""
	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"
)

// reason values reported in result.Reason.
const (
	reasonInvalidArgs        = "invalid_args"
	reasonResolveFailed      = "resolve_failed"
	reasonListenFailed       = "listen_failed"
	reasonTimeout            = "timeout"
	reasonTLSRejected        = "tls_rejected"
	reasonVersionNegotiation = "version_negotiation"
	reasonStatelessReset     = "stateless_reset"
	reasonTransportError     = "transport_error"
	reasonApplicationError   = "application_error"
	reasonOther              = "other"
)

type result struct {
	Supported    bool          `json:"supported"`
	ALPN         string        `json:"alpn,omitempty"`
	TLSVersion   string        `json:"tls_version,omitempty"`
	ServerAddr   string        `json:"server_addr,omitempty"`
	Family       string        `json:"family,omitempty"`
	TargetIP     string        `json:"target_ip,omitempty"`
	HandshakeMs  int64         `json:"handshake_ms"`
	Reason       string        `json:"reason,omitempty"`
	TLSAlert     string        `json:"tls_alert,omitempty"`
	TLSAlertCode int           `json:"tls_alert_code,omitempty"`
	AltSvc       *altSvcResult `json:"alt_svc,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// altSvcResult is the outcome of the optional TLS-over-TCP Alt-Svc check.
type altSvcResult struct {
	H3     bool   `json:"h3"`               // Alt-Svc advertises h3 (or an h3-NN draft)
	Header string `json:"header,omitempty"` // raw Alt-Svc header value
	ALPN   string `json:"alpn,omitempty"`   // protocol negotiated over TCP
	Status int    `json:"status,omitempty"` // HTTP status of the HEAD request
	Error  string `json:"error,omitempty"`
}

// options describes one probe.
type options struct {
	Host    string
	IP      netip.Addr // zero value means "resolve Host"
	Family  string     // familyAny, familyIPv4 or familyIPv6
	Port    int
	Timeout time.Duration
	AltSvc  bool
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		writeResult(result{Reason: reasonInvalidArgs, Error: err.Error()})
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
	port := fs.Int("p", quicPort, "port to probe")
	timeoutSec := fs.Int("t", 0, "timeout in seconds")
	altSvc := fs.Bool("altsvc", false, "also check the Alt-Svc header over TCP")
	if err := fs.Parse(args); err != nil {
		return options{}, fmt.Errorf("%s: %w", usageText, err)
	}
	if fs.NArg() < 1 || fs.NArg() > 2 || fs.Arg(0) == "" {
		return options{}, errors.New(usageText)
	}
	if *port < 1 || *port > 65535 {
		return options{}, fmt.Errorf("invalid -p %d: port must be 1-65535", *port)
	}
	opts := options{
		Host:    fs.Arg(0),
		Port:    *port,
		Timeout: parseTimeout(fs, *timeoutSec),
		AltSvc:  *altSvc,
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

// parseTimeout applies, in increasing precedence: the default, the legacy
// positional timeout, and the -t flag.
func parseTimeout(fs *flag.FlagSet, flagSec int) time.Duration {
	timeout := defaultTimeoutSec * time.Second
	if fs.NArg() == 2 {
		if v, err := strconv.Atoi(fs.Arg(1)); err == nil && v > 0 {
			timeout = time.Duration(v) * time.Second
		}
	}
	if flagSec > 0 {
		timeout = time.Duration(flagSec) * time.Second
	}
	return timeout
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
		return result{
			Family:      opts.Family,
			HandshakeMs: time.Since(start).Milliseconds(),
			Reason:      reasonResolveFailed,
			Error:       err.Error(),
		}
	}

	r := dialQUIC(ctx, opts, target)
	r.HandshakeMs = time.Since(start).Milliseconds()
	if opts.AltSvc {
		r.AltSvc = checkAltSvc(opts, target)
	}
	return r
}

// dialQUIC performs the QUIC handshake to target and fills every result
// field except HandshakeMs and AltSvc.
func dialQUIC(ctx context.Context, opts options, target netip.Addr) result {
	family := familyOf(target)
	base := result{Family: family, TargetIP: target.String()}

	udpConn, err := net.ListenUDP(udpNetwork(family), nil)
	if err != nil {
		base.Reason = reasonListenFailed
		base.Error = "listen udp: " + err.Error()
		return base
	}
	defer udpConn.Close()

	tlsConf := &tls.Config{
		ServerName:         opts.Host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}
	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(target, uint16(opts.Port)))
	conn, err := quic.Dial(ctx, udpConn, remote, tlsConf, nil)
	if err != nil {
		base.Reason, base.TLSAlert, base.TLSAlertCode = classifyError(err)
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

// classifyError maps a quic.Dial error to a reason. For TLS rejections it
// also returns the decoded alert name and number.
func classifyError(err error) (reason, alert string, alertCode int) {
	var (
		transportErr *quic.TransportError
		appErr       *quic.ApplicationError
		vnErr        *quic.VersionNegotiationError
		resetErr     *quic.StatelessResetError
		hsTimeout    *quic.HandshakeTimeoutError
		idleTimeout  *quic.IdleTimeoutError
	)
	switch {
	case err == nil:
		return "", "", 0
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &hsTimeout), errors.As(err, &idleTimeout):
		return reasonTimeout, "", 0
	case errors.As(err, &transportErr):
		if transportErr.ErrorCode.IsCryptoError() {
			alert, alertCode = describeAlert(transportErr.ErrorCode)
			return reasonTLSRejected, alert, alertCode
		}
		return reasonTransportError, "", 0
	case errors.As(err, &vnErr):
		return reasonVersionNegotiation, "", 0
	case errors.As(err, &resetErr):
		return reasonStatelessReset, "", 0
	case errors.As(err, &appErr):
		return reasonApplicationError, "", 0
	default:
		return reasonOther, "", 0
	}
}

// describeAlert decodes a QUIC crypto error code (0x100 + TLS alert) into
// the alert's name and number, reusing Go's own alert table.
func describeAlert(code quic.TransportErrorCode) (string, int) {
	if !code.IsCryptoError() {
		return "", 0
	}
	n := int(code - 0x100)
	name := strings.TrimPrefix(tls.AlertError(uint8(n)).Error(), "tls: ")
	return name, n
}

// checkAltSvc makes a TLS-over-TCP HEAD request to target (with opts.Host
// as SNI and Host header) and reports the Alt-Svc header. It never fails
// the probe; problems are recorded in the returned struct.
func checkAltSvc(opts options, target netip.Addr) *altSvcResult {
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	addr := net.JoinHostPort(target.String(), strconv.Itoa(opts.Port))
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         opts.Host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := "https://" + net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return &altSvcResult{Error: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &altSvcResult{Error: err.Error()}
	}
	defer resp.Body.Close()

	out := &altSvcResult{Status: resp.StatusCode, Header: resp.Header.Get("Alt-Svc")}
	out.H3 = hasH3Token(out.Header)
	if resp.TLS != nil {
		out.ALPN = resp.TLS.NegotiatedProtocol
	}
	return out
}

// hasH3Token reports whether an Alt-Svc header value advertises HTTP/3,
// either the final "h3" token or a draft such as "h3-29".
func hasH3Token(header string) bool {
	for _, entry := range strings.Split(header, ",") {
		proto, _, _ := strings.Cut(strings.TrimSpace(entry), "=")
		proto = strings.TrimSpace(proto)
		if proto == "h3" || strings.HasPrefix(proto, "h3-") {
			return true
		}
	}
	return false
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
