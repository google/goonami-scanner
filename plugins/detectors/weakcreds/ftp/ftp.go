/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package ftp provides a Goonami weak credentials detector ("dt/wk/ftp") for
// FTP and FTPS services by migrating Tsunami's NcrackCredentialTester FTP support.
package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"

	networkpb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	networkservicepb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vulnerabilitypb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const (
	moduleName = "dt/wk/ftp"

	defaultTimeout                = 8 * time.Second
	maxConsecutiveTransportErrors = 5
	maxSessionBytes               = 64 * 1024
	maxReplyLines                 = 64

	probeUser     = "goonami-ftp-probe"
	probePassword = "goonami-ftp-invalid-probe-password"
)

var (
	// ErrAuthFailed indicates the FTP server rejected the provided credentials.
	ErrAuthFailed = errors.New("ftp: authentication failed")

	// ErrNotFTPService indicates the target network service is not a valid FTP service.
	ErrNotFTPService = errors.New("ftp: target is not an FTP service")

	// ErrAuthUnsupported indicates the FTP server rejected USER/PASS authentication mechanism.
	ErrAuthUnsupported = errors.New("ftp: password authentication unsupported")
)

func init() {
	module.RegisterDetector(moduleName, New)
}

// DefaultCredentials returns FTP-specific default credentials tested before the
// generic credential wordlist.
func DefaultCredentials() []bruteforce.Credential {
	return []bruteforce.Credential{
		{Username: "anonymous", Password: ""},
		{Username: "anonymous", Password: "anonymous"},
		{Username: "anonymous", Password: "anonymous@example.com"},
		{Username: "ftp", Password: ""},
		{Username: "ftp", Password: "ftp"},
		{Username: "root", Password: "toor"},
	}
}

// New creates a new FTP weak credentials detector backed by the generic
// brute-force library.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return NewWithOptions(ctx, cfg, nil)
}

// NewWithOptions creates a new FTP weak credentials detector with custom
// brute-force options. When opts is nil, the default credential store is loaded
// with FTP default credentials, an empty password ("") prepended per user, and
// "anonymous" scoped strictly to anonymous passwords rather than full wordlists.
func NewWithOptions(ctx context.Context, cfg *config.Config, opts *bruteforce.Options) (*bruteforce.Detector, error) {
	if cfg == nil {
		return nil, bruteforce.ErrConfigNil
	}
	if opts == nil {
		baseStore, err := credentialstore.NewWithDefaults()
		if err != nil {
			return nil, err
		}
		store := credentialstore.New()
		for _, user := range baseStore.Usernames() {
			_ = store.AddUser(user)
			if user == "anonymous" {
				continue
			}
			_ = store.AddPasswordForUser(user, "")
			store.AddMultiplePasswordsForUser(user, baseStore.Passwords(user))
		}
		opts = &bruteforce.Options{
			CredentialStore:    store,
			DefaultCredentials: DefaultCredentials(),
		}
	}
	handler := NewHandler(cfg)
	return bruteforce.New(ctx, cfg, handler, opts)
}

// Handler implements bruteforce.Handler for FTP and FTPS authentication.
type Handler struct {
	timeout          time.Duration
	explicitTLSAddrs sync.Map
}

// NewHandler creates a new FTP brute-force handler using the provided configuration.
func NewHandler(cfg *config.Config) *Handler {
	timeout := defaultTimeout
	if cfg != nil {
		if secs := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); secs > 0 {
			candidate := time.Duration(secs) * time.Second
			if candidate < timeout {
				timeout = candidate
			}
		}
	}
	return &Handler{timeout: timeout}
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return moduleName
}

// Close releases resources held by the handler.
func (h *Handler) Close() error {
	return nil
}

// Vulnerability returns the base vulnerability metadata reported when weak FTP
// credentials are discovered.
func (h *Handler) Vulnerability() *vulnerabilitypb.Vulnerability {
	return vulnerabilitypb.Vulnerability_builder{
		MainId: vulnerabilitypb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "WEAK_CREDENTIALS_FOR_FTP",
		}.Build(),
		Severity:       vulnerabilitypb.Severity_CRITICAL,
		Title:          "Weak 'ftp' service credential",
		Description:    "Well known or weak credentials are detected for 'ftp' service.",
		Recommendation: "Change the password of all affected users to a strong one.",
	}.Build()
}

type ftpWorker struct {
	handler           *Handler
	consecutiveErrors int
}

// NewWorker returns a Worker for testing FTP credentials sequentially.
func (h *Handler) NewWorker() bruteforce.Worker {
	return &ftpWorker{handler: h}
}

func (w *ftpWorker) Close() error {
	return w.handler.Close()
}

func (w *ftpWorker) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
	ok, err := w.handler.TestCredential(ctx, service, cred)
	if err == nil {
		w.consecutiveErrors = 0
		return ok, nil
	}
	if errors.Is(err, bruteforce.ErrStopBruteForce) || ctx.Err() != nil {
		return false, err
	}
	w.consecutiveErrors++
	if w.consecutiveErrors >= maxConsecutiveTransportErrors {
		log.DebugContextf(ctx, log.DebugLevelService, "stopping FTP brute force after %d consecutive transport errors: %v", w.consecutiveErrors, err) // NOMUTANTS -- diagnostic logging
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
	}
	log.DebugContextf(ctx, log.DebugLevelRequest, "FTP authentication attempt for %q failed: %v", cred.Username, err) // NOMUTANTS -- diagnostic logging
	return false, nil
}

// Fingerprint verifies whether the target network service is an FTP or FTPS
// server that accepts USER/PASS authentication before brute-forcing credentials.
func (h *Handler) Fingerprint(ctx context.Context, service *networkservicepb.NetworkService) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if netservice.IsWebService(service) {
		return false, nil
	}
	if proto := service.GetTransportProtocol(); proto != networkpb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != networkpb.TransportProtocol_TCP {
		return false, nil
	}

	addr, serverName, err := resolveDialTarget(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	implicitTLS := useImplicitTLS(service)
	connCtx, cancel := context.WithTimeout(ctx, h.timeout) // NOMUTANTS -- defensive per-probe timeout
	defer cancel()                                         // NOMUTANTS -- defensive context cleanup

	matched, useExplicitTLS, err := fingerprintTarget(connCtx, addr, serverName, implicitTLS)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "FTP fingerprint probe failed for %q: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return false, nil
	}
	if useExplicitTLS {
		h.explicitTLSAddrs.Store(addr, true)
	}
	return matched, nil
}

// TestCredential attempts to authenticate against the FTP or FTPS service using
// the provided credential and verifies an active authenticated session.
func (h *Handler) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if containsCRLF(cred.Username) || containsCRLF(cred.Password) {
		return false, nil
	}

	addr, serverName, err := resolveDialTarget(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	implicitTLS := useImplicitTLS(service)
	_, explicitTLS := h.explicitTLSAddrs.Load(addr)

	connCtx, cancel := context.WithTimeout(ctx, h.timeout) // NOMUTANTS -- defensive per-attempt timeout
	defer cancel()                                         // NOMUTANTS -- defensive context cleanup

	ok, err := attemptSingleAuth(connCtx, addr, serverName, implicitTLS, explicitTLS, cred)
	if err != nil && errors.Is(err, ErrAuthFailed) && explicitTLS && isAnonymousUser(cred.Username) {
		// vsftpd defaults to force_local_logins_ssl=YES with allow_anon_ssl=NO,
		// rejecting anonymous logins over TLS with 530 while permitting cleartext anonymous login.
		if clearOK, clearErr := attemptSingleAuth(connCtx, addr, serverName, false, false, cred); clearErr == nil && clearOK {
			return true, nil
		}
	}

	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if errors.Is(err, ErrAuthFailed) {
			return false, nil
		}
		if errors.Is(err, ErrAuthUnsupported) {
			return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
		}
		return false, err
	}
	return ok, nil
}

func attemptSingleAuth(ctx context.Context, addr, serverName string, implicitTLS, explicitTLS bool, cred bruteforce.Credential) (bool, error) {
	fc, err := dialFTP(ctx, addr, serverName, implicitTLS)
	if err != nil {
		return false, err
	}
	defer fc.close()

	if explicitTLS {
		if ok, tlsErr := fc.upgradeExplicitTLS(ctx, serverName); !ok {
			return false, tlsErr
		}
	}
	return authenticateAndVerify(fc, cred.Username, cred.Password)
}

func resolveDialTarget(ep *networkpb.NetworkEndpoint) (addr string, serverName string, err error) {
	authorities, err := netendpoint.ToURIAuthorities(ep)
	if err != nil {
		return "", "", err
	}
	serverName = ep.GetHostname().GetName()
	// Prefer the direct IP:port authority (last entry when both hostname and IP
	// are present) so TCP dialing avoids redundant DNS lookups and IPv6 ::1
	// fallback delays when scanning IPv4 loopback or dual-stack hostnames.
	return authorities[len(authorities)-1], serverName, nil
}

func isAnonymousUser(user string) bool {
	return strings.EqualFold(user, "anonymous") || strings.EqualFold(user, "ftp")
}

func useImplicitTLS(service *networkservicepb.NetworkService) bool {
	if netservice.HasTLS(service) {
		return true
	}
	return strings.EqualFold(service.GetServiceName(), "ftps")
}

func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func newTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // NOLINT
	}
}

type ftpConn struct {
	conn   net.Conn
	reader *bufio.Reader
	stop   func() bool
}

func dialFTP(ctx context.Context, addr, serverName string, implicitTLS bool) (*ftpConn, error) {
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotFTPService, err)
	}

	if deadline, ok := ctx.Deadline(); ok { // NOMUTANTS -- defensive socket deadline propagation
		_ = rawConn.SetDeadline(deadline) // NOMUTANTS -- defensive socket deadline propagation
	}

	var activeConn net.Conn = rawConn
	if implicitTLS {
		tlsConn := tls.Client(rawConn, newTLSConfig(serverName))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("%w: %w", ErrNotFTPService, err)
		}
		activeConn = tlsConn
	}

	stop := context.AfterFunc(ctx, func() {
		_ = activeConn.Close()
	})

	fc := &ftpConn{
		conn:   activeConn,
		reader: bufio.NewReader(io.LimitReader(activeConn, maxSessionBytes)), // NOMUTANTS -- defensive stream bound
		stop:   stop,
	}

	code, banner, err := fc.readReply()
	if err == nil && code == 120 {
		// RFC 959 allows a preliminary 120 ("Service ready in nnn minutes") reply before 220.
		code, banner, err = fc.readReply()
	}
	if err != nil {
		fc.close()
		return nil, err
	}
	if code != 220 || isSMTPBanner(banner) {
		fc.close()
		return nil, fmt.Errorf("%w: unexpected greeting %d", ErrNotFTPService, code)
	}
	return fc, nil
}

func (fc *ftpConn) close() {
	if fc.stop != nil {
		fc.stop()
	}
	if fc.conn != nil {
		_ = fc.conn.Close()
	}
}

func (fc *ftpConn) upgradeExplicitTLS(ctx context.Context, serverName string) (bool, error) {
	code, _, err := fc.cmd("AUTH TLS")
	if err != nil {
		return false, err
	}
	if code != 234 {
		return false, fmt.Errorf("%w: AUTH TLS returned %d", ErrAuthUnsupported, code)
	}

	if fc.stop != nil {
		fc.stop()
	}
	tlsConn := tls.Client(fc.conn, newTLSConfig(serverName))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false, fmt.Errorf("%w: %w", ErrNotFTPService, err)
	}
	fc.conn = tlsConn
	fc.reader = bufio.NewReader(io.LimitReader(tlsConn, maxSessionBytes)) // NOMUTANTS -- defensive stream bound
	fc.stop = context.AfterFunc(ctx, func() {
		_ = tlsConn.Close()
	})
	return true, nil
}

func (fc *ftpConn) cmd(command string) (int, string, error) {
	if _, err := io.WriteString(fc.conn, command+"\r\n"); err != nil {
		return 0, "", fmt.Errorf("%w: %w", ErrNotFTPService, err)
	}
	return fc.readReply()
}

func (fc *ftpConn) readReply() (int, string, error) {
	firstLine, err := fc.readLine()
	if err != nil {
		return 0, "", err
	}
	code, sep, ok := parseReplyPrefix(firstLine)
	if !ok {
		return 0, "", fmt.Errorf("%w: malformed reply %q", ErrNotFTPService, firstLine)
	}
	if sep != '-' {
		return code, firstLine, nil
	}

	wantPrefix := firstLine[:3] + " "
	var b strings.Builder
	b.WriteString(firstLine)
	for range maxReplyLines { // NOMUTANTS -- defensive bound on multi-line banner length
		line, err := fc.readLine()
		if err != nil {
			return 0, "", err
		}
		b.WriteByte('\n')
		b.WriteString(line)
		if strings.HasPrefix(line, wantPrefix) {
			return code, b.String(), nil
		}
	}
	return 0, "", fmt.Errorf("%w: multi-line reply exceeded limit", ErrNotFTPService)
}

func (fc *ftpConn) readLine() (string, error) {
	line, err := fc.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFTPService, err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func parseReplyPrefix(line string) (int, byte, bool) {
	if len(line) < 3 {
		return 0, 0, false
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 599 {
		return 0, 0, false
	}
	if len(line) == 3 {
		return code, ' ', true
	}
	sep := line[3]
	if sep != ' ' && sep != '-' {
		return 0, 0, false
	}
	return code, sep, true
}

func isSMTPBanner(banner string) bool {
	lower := strings.ToLower(banner)
	for _, field := range strings.Fields(lower) {
		trimmed := strings.Trim(field, "(),;[]<>")
		if trimmed == "smtp" || trimmed == "esmtp" || trimmed == "lmtp" {
			return true
		}
	}
	return false
}

func isSMTPEnhancedRejection(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "5.7.") || strings.Contains(lower, "starttls")
}

func fingerprintTarget(ctx context.Context, addr, serverName string, implicitTLS bool) (matched bool, explicitTLS bool, err error) {
	fc, err := dialFTP(ctx, addr, serverName, implicitTLS)
	if err != nil {
		return false, false, err
	}
	defer fc.close()

	if !implicitTLS {
		// Probe AUTH TLS (RFC 4217) before cleartext USER so mandatory-FTPS
		// daemons (such as Pure-FTPd TLS=2, which replies 421 and closes the
		// socket on cleartext USER, or ProFTPD/FileZilla per-user TLS policies)
		// negotiate TLS cleanly without dropping the connection.
		tlsOK, tlsErr := fc.upgradeExplicitTLS(ctx, serverName)
		if tlsOK {
			ok, probeErr := probeUserOnConn(fc)
			return ok, ok, probeErr
		}
		if tlsErr != nil && !errors.Is(tlsErr, ErrAuthUnsupported) {
			// Server closed the connection on AUTH TLS or failed TLS handshake;
			// redial once to test plain cleartext FTP.
			fc.close()
			fc, err = dialFTP(ctx, addr, serverName, false)
			if err != nil {
				return false, false, err
			}
			defer fc.close()
		}
	}

	ok, err := probeUserOnConn(fc)
	return ok, false, err
}

func probeUserOnConn(fc *ftpConn) (bool, error) {
	code, msg, err := fc.cmd("USER " + probeUser)
	if err != nil {
		return false, err
	}

	switch code {
	case 331, 332:
		pCode, _, pErr := fc.cmd("PASS " + probePassword)
		if pErr != nil {
			return false, pErr
		}
		if pCode == 530 || pCode == 430 || pCode == 332 || pCode == 550 {
			_, _, _ = fc.cmd("QUIT")
			return true, nil
		}
		if pCode == 230 || pCode == 202 {
			return verifyLoggedIn(fc)
		}
		return false, nil
	case 230:
		return verifyLoggedIn(fc)
	case 530, 550:
		if isSMTPEnhancedRejection(msg) {
			return false, nil
		}
		return verifyPreAuthFTPFeature(fc), nil
	default:
		return false, nil
	}
}

func verifyPreAuthFTPFeature(fc *ftpConn) bool {
	featCode, _, featErr := fc.cmd("FEAT")
	if featErr == nil && featCode == 211 {
		_, _, _ = fc.cmd("QUIT")
		return true
	}
	if featErr == nil && (featCode == 500 || featCode == 502) {
		systCode, _, systErr := fc.cmd("SYST")
		if systErr == nil && systCode == 215 {
			_, _, _ = fc.cmd("QUIT")
			return true
		}
	}
	return false
}

func authenticateAndVerify(fc *ftpConn, username, password string) (bool, error) {
	code, _, err := fc.cmd("USER " + username)
	if err != nil {
		return false, err
	}

	switch code {
	case 230:
		return verifyLoggedIn(fc)
	case 331, 332:
		pCode, _, pErr := fc.cmd("PASS " + password)
		if pErr != nil {
			return false, pErr
		}
		switch pCode {
		case 230, 202:
			return verifyLoggedIn(fc)
		case 530, 430, 332, 550, 501, 553:
			_, _, _ = fc.cmd("QUIT")
			return false, ErrAuthFailed
		case 421:
			return false, ErrNotFTPService
		default:
			return false, ErrAuthUnsupported
		}
	case 530, 430, 550, 501, 553:
		_, _, _ = fc.cmd("QUIT")
		return false, ErrAuthFailed
	case 421:
		return false, ErrNotFTPService
	case 534, 503, 504:
		return false, ErrAuthUnsupported
	default:
		return false, ErrNotFTPService
	}
}

func verifyLoggedIn(fc *ftpConn) (bool, error) {
	code, msg, err := fc.cmd("PWD")
	if err != nil {
		return false, err
	}
	if code == 257 && strings.Contains(msg, `"`) {
		_, _, _ = fc.cmd("QUIT")
		return true, nil
	}
	if code == 500 || code == 502 || code == 550 {
		if code != 550 {
			xpwdCode, xpwdMsg, xpwdErr := fc.cmd("XPWD")
			if xpwdErr != nil {
				return false, xpwdErr
			}
			if xpwdCode == 257 && strings.Contains(xpwdMsg, `"`) {
				_, _, _ = fc.cmd("QUIT")
				return true, nil
			}
		}
		cwdCode, _, cwdErr := fc.cmd("CWD .")
		if cwdErr != nil {
			return false, cwdErr
		}
		if cwdCode == 250 {
			_, _, _ = fc.cmd("QUIT")
			return true, nil
		}
	}
	return false, ErrNotFTPService
}
