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

// Package redis implements a Goonami weak credentials detector ("dt/wk/redis")
// for Redis and RESP-compatible services, migrated from Tsunami's Ncrack Redis
// weak credential tester.
package redis

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
	"time"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

const (
	// ModuleName is the unique module identifier for the Redis weak credentials detector.
	ModuleName = "dt/wk/redis"

	defaultTimeout                = 5 * time.Second
	maxConsecutiveTransportErrors = 3
	maxLineBytes                  = 4096
	maxBulkBytes                  = 65536

	probeUser     = "goonami_fp_probe"
	probePassword = "goonami_fp_probe_invalid_pass_9f8a7b"
)

var (
	// ErrPasswordAuthUnsupported indicates the Redis server does not require or accept
	// password authentication (for example, unauthenticated mode or protected-mode denial).
	ErrPasswordAuthUnsupported = errors.New("Redis server does not support or require password authentication")

	// ErrNotRedisService indicates the target did not speak valid RESP or could not be reached.
	ErrNotRedisService = errors.New("target is not a reachable Redis RESP service")
)

func init() {
	module.RegisterDetector(ModuleName, New)
}

// DefaultCredentials returns high-priority default Redis credentials to test first,
// covering both legacy requirepass ("default" user) and common Redis 6+ ACL accounts.
func DefaultCredentials() []bruteforce.Credential {
	return []bruteforce.Credential{
		{Username: "default", Password: ""},
		{Username: "default", Password: "redis"},
		{Username: "default", Password: "foobared"},
		{Username: "default", Password: "password"},
		{Username: "default", Password: "admin"},
		{Username: "default", Password: "root"},
		{Username: "default", Password: "123456"},
		{Username: "redis", Password: "redis"},
		{Username: "admin", Password: "admin"},
		{Username: "root", Password: "root"},
	}
}

// BaseVulnerability returns the base vulnerability metadata reported when weak Redis
// credentials are discovered.
func BaseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "WEAK_CREDENTIALS_FOR_REDIS",
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          "Weak 'redis' service credential",
		Description:    "Well known or weak credentials are detected for 'redis' service.",
		Recommendation: "Change the password of all affected users to a strong one and restrict network access to the Redis service.",
	}.Build()
}

// Handler implements bruteforce.Handler for Redis RESP password and ACL authentication.
type Handler struct {
	timeout time.Duration
}

// NewHandler creates a new Redis brute-force handler using timeout settings from cfg.
func NewHandler(cfg *config.Config) *Handler {
	timeout := defaultTimeout
	if cfg != nil && cfg.GlobalConfig() != nil && cfg.GlobalConfig().GetPerformance() != nil {
		if secs := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); secs > 0 {
			configured := time.Duration(secs) * time.Second
			if configured < timeout {
				timeout = configured
			}
		}
	}
	return &Handler{timeout: timeout}
}

// New creates a new Redis weak credentials detector seeded with default Redis credentials
// and the top common password list.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	baseStore, err := credentialstore.NewWithDefaults()
	if err != nil {
		return nil, err // NOMUTANTS -- embedded credential store load only fails on corrupt binary build
	}
	baseStore.CollapseToPasswordOnly()
	commonPasswords := baseStore.Passwords("")

	store := credentialstore.New()
	aclPasswords := []string{"redis", "admin", "root", "password", "123456", "foobared"}
	for _, aclUser := range []string{"redis", "admin", "root"} {
		_ = store.AddUser(aclUser)
		store.AddMultiplePasswordsForUser(aclUser, aclPasswords)
	}
	_ = store.AddUser("default")
	store.AddMultiplePasswordsForUser("default", commonPasswords)

	return NewWithOptions(ctx, cfg, &bruteforce.Options{
		CredentialStore:    store,
		DefaultCredentials: DefaultCredentials(),
	})
}

// NewWithOptions creates a new Redis weak credentials detector with custom brute-force options.
func NewWithOptions(ctx context.Context, cfg *config.Config, opts *bruteforce.Options) (*bruteforce.Detector, error) {
	return bruteforce.New(ctx, cfg, NewHandler(cfg), opts)
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return ModuleName
}

// Vulnerability returns the base vulnerability metadata reported when weak credentials are found.
func (h *Handler) Vulnerability() *vpb.Vulnerability {
	return BaseVulnerability()
}

// NewWorker returns a stateful bruteforce.Worker that reuses a persistent RESP connection
// across sequential credential attempts within a single worker goroutine.
func (h *Handler) NewWorker() bruteforce.Worker {
	return &redisWorker{handler: h}
}

// Fingerprint verifies whether the target service is a Redis server that actively enforces
// password or ACL authentication before starting brute-force attempts.
func (h *Handler) Fingerprint(ctx context.Context, service *nspb.NetworkService) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if netservice.IsWebService(service) {
		return false, nil
	}
	if tp := service.GetTransportProtocol(); tp != npb.TransportProtocol_TCP && tp != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED {
		return false, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	conn, reader, err := h.dial(ctx, addr, netservice.HasTLS(service))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Redis dial failed for %q: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return false, nil
	}
	defer conn.Close()

	pingReply, err := sendCommand(conn, reader, h.timeout, "PING")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Redis PING probe failed for %q: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return false, nil
	}

	if isNoAuthError(pingReply) {
		// Confirm the server genuinely validates credentials and rejects an invalid probe password
		// (ruling out accept-all honeypots and non-password configurations).
		authReply, authErr := sendCommand(conn, reader, h.timeout, "AUTH", probePassword)
		if authErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			return false, nil
		}
		if isAuthInvalidError(authReply) {
			return true, nil
		}
		// In Redis 6+/Valkey, 'user default off' retains USER_FLAG_NOPASS on DefaultUser, so 1-arg
		// AUTH returns 'without any password configured for the default user' while named ACL users
		// still accept 2-arg AUTH.
		if isDefaultUserNoPassError(authReply) {
			aclReply, aclErr := sendCommand(conn, reader, h.timeout, "AUTH", probeUser, probePassword)
			if aclErr != nil {
				return false, ctx.Err()
			}
			return isAuthInvalidError(aclReply), nil
		}
		return false, nil
	}

	if isNoPermError(pingReply) {
		// When 'user default on nopass -@all' (without +ping), new connections auto-bind to
		// 'default' and PING returns -NOPERM; verify 2-arg ACL AUTH is active.
		aclReply, aclErr := sendCommand(conn, reader, h.timeout, "AUTH", probeUser, probePassword)
		if aclErr != nil {
			return false, ctx.Err()
		}
		return isAuthInvalidError(aclReply), nil
	}

	if pingReply.kind == '+' && strings.EqualFold(pingReply.text, "PONG") {
		// Default user is allowed to execute PING without AUTH. Check INFO server:
		// if INFO server succeeds with redis_version/valkey_version, the server is completely
		// unauthenticated (covered by unauthenticated Redis RCE detection, not weak credentials).
		// If INFO server returns -NOPERM or -NOAUTH, default user is ACL-restricted and named ACL
		// users may still authenticate via 2-argument AUTH.
		infoReply, infoErr := sendCommand(conn, reader, h.timeout, "INFO", "server")
		if infoErr != nil {
			return false, ctx.Err()
		}
		if isNoPermError(infoReply) || isNoAuthError(infoReply) {
			authReply, authErr := sendCommand(conn, reader, h.timeout, "AUTH", probeUser, probePassword)
			if authErr != nil {
				return false, ctx.Err()
			}
			return isAuthInvalidError(authReply), nil
		}
		return false, nil
	}

	return false, nil
}

func (h *Handler) dial(ctx context.Context, addr string, useTLS bool) (net.Conn, *bufio.Reader, error) {
	netDialer := &net.Dialer{Timeout: h.timeout} // NOMUTANTS -- defensive dial timeout
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		tlsDialer := &tls.Dialer{
			NetDialer: netDialer,
			Config: &tls.Config{
				InsecureSkipVerify: true, // NOLINT
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = netDialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReaderSize(conn, maxLineBytes), nil
}

type redisWorker struct {
	handler           *Handler
	addr              string
	useTLS            bool
	conn              net.Conn
	reader            *bufio.Reader
	consecutiveErrors int
	defaultUserNoPass bool
}

func (w *redisWorker) Close() error {
	w.resetConn()
	return nil
}

func (w *redisWorker) resetConn() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
		w.reader = nil
	}
}

func (w *redisWorker) TestCredential(ctx context.Context, service *nspb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	useTLS := netservice.HasTLS(service)
	ok, err := w.tryCredential(ctx, addr, useTLS, cred)
	if err == nil {
		w.consecutiveErrors = 0
		return ok, nil
	}
	if errors.Is(err, bruteforce.ErrStopBruteForce) || ctx.Err() != nil {
		return false, err
	}

	w.consecutiveErrors++
	if w.consecutiveErrors >= maxConsecutiveTransportErrors {
		log.DebugContextf(ctx, log.DebugLevelService, "stopping Redis brute force after %d consecutive transport errors: %v", w.consecutiveErrors, err) // NOMUTANTS -- diagnostic logging
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
	}
	log.DebugContextf(ctx, log.DebugLevelRequest, "Redis authentication attempt for %q failed: %v", cred.Username, err) // NOMUTANTS -- diagnostic logging
	return false, nil
}

func (w *redisWorker) tryCredential(ctx context.Context, addr string, useTLS bool, cred bruteforce.Credential) (bool, error) {
	if (cred.Username == "" || cred.Username == "default") && w.defaultUserNoPass && w.addr == addr {
		return false, nil
	}

	reused := w.conn != nil && w.addr == addr && w.useTLS == useTLS
	if !reused {
		if w.addr != addr {
			w.defaultUserNoPass = false
		}
		w.resetConn()
		conn, reader, err := w.handler.dial(ctx, addr, useTLS)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			return false, fmt.Errorf("%w: %w", ErrNotRedisService, err)
		}
		w.conn = conn
		w.reader = reader
		w.addr = addr
		w.useTLS = useTLS
	}

	ok, err := w.authOnce(cred)
	if err != nil && reused && !errors.Is(err, bruteforce.ErrStopBruteForce) {
		// Reused socket may have been closed by the server between attempts; reconnect once.
		w.resetConn()
		conn, reader, dialErr := w.handler.dial(ctx, addr, useTLS)
		if dialErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			return false, fmt.Errorf("%w: %w", ErrNotRedisService, dialErr)
		}
		w.conn = conn
		w.reader = reader
		w.addr = addr
		w.useTLS = useTLS
		ok, err = w.authOnce(cred)
	}
	if err != nil {
		w.resetConn()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, err
	}
	return ok, nil
}

func (w *redisWorker) authOnce(cred bruteforce.Credential) (bool, error) {
	isDefaultUser := cred.Username == "" || cred.Username == "default"
	var authArgs []string
	if isDefaultUser {
		authArgs = []string{"AUTH", cred.Password}
	} else {
		authArgs = []string{"AUTH", cred.Username, cred.Password}
	}

	reply, err := sendCommand(w.conn, w.reader, w.handler.timeout, authArgs...)
	if err != nil {
		return false, err
	}

	if reply.kind == '+' && reply.text == "OK" {
		// Verify session state transition on the same connection, then close so subsequent
		// attempts for other users do not inherit the authenticated session.
		pingReply, pingErr := sendCommand(w.conn, w.reader, w.handler.timeout, "PING")
		w.resetConn()
		if pingErr != nil {
			return false, pingErr
		}
		if (pingReply.kind == '+' && strings.EqualFold(pingReply.text, "PONG")) || isNoPermError(pingReply) {
			return true, nil
		}
		return false, ErrNotRedisService
	}

	if isAuthInvalidError(reply) || (!isDefaultUser && isTwoArgAuthUnsupportedError(reply)) {
		return false, nil
	}
	if isDefaultUser && isDefaultUserNoPassError(reply) {
		// Redis 6+/Valkey DefaultUser has USER_FLAG_NOPASS (e.g. 'user default off' or
		// 'user default on nopass -@all +ping'); skip remaining default-user attempts while
		// continuing to test named ACL users.
		w.defaultUserNoPass = true
		return false, nil
	}
	if isLegacyNoPasswordSetError(reply) || isServiceDeniedError(reply) {
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, ErrPasswordAuthUnsupported)
	}
	return false, ErrNotRedisService
}

type respReply struct {
	kind byte
	text string
}

func encodeRESPCommand(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return []byte(b.String())
}

func sendCommand(conn net.Conn, reader *bufio.Reader, timeout time.Duration, args ...string) (respReply, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout)) // NOMUTANTS -- defensive socket deadline prevents hung I/O
	if _, err := conn.Write(encodeRESPCommand(args...)); err != nil {
		return respReply{}, fmt.Errorf("%w: %w", ErrNotRedisService, err)
	}
	return readRESPReply(reader)
}

func readRESPReply(reader *bufio.Reader) (respReply, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return respReply{}, fmt.Errorf("%w: %w", ErrNotRedisService, err)
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return respReply{}, ErrNotRedisService
	}

	kind := line[0]
	payload := string(line[1 : len(line)-2])
	switch kind {
	case '+', '-':
		return respReply{kind: kind, text: payload}, nil
	case '$':
		n, convErr := strconv.Atoi(payload)
		if convErr != nil || n < -1 || n > maxBulkBytes {
			return respReply{}, ErrNotRedisService
		}
		if n == -1 {
			return respReply{kind: '$', text: ""}, nil
		}
		buf := make([]byte, n+2)
		if _, readErr := io.ReadFull(reader, buf); readErr != nil {
			return respReply{}, fmt.Errorf("%w: %w", ErrNotRedisService, readErr)
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return respReply{}, ErrNotRedisService
		}
		return respReply{kind: '$', text: string(buf[:n])}, nil
	default:
		return respReply{}, ErrNotRedisService
	}
}

func hasErrorPrefix(text, prefix string) bool {
	if len(text) < len(prefix) {
		return false
	}
	if !strings.EqualFold(text[:len(prefix)], prefix) {
		return false
	}
	return len(text) == len(prefix) || text[len(prefix)] == ' '
}

func isNoAuthError(r respReply) bool {
	return r.kind == '-' && hasErrorPrefix(r.text, "NOAUTH")
}

func isNoPermError(r respReply) bool {
	return r.kind == '-' && hasErrorPrefix(r.text, "NOPERM")
}

func isAuthInvalidError(r respReply) bool {
	if r.kind != '-' {
		return false
	}
	if hasErrorPrefix(r.text, "WRONGPASS") {
		return true
	}
	lower := strings.ToLower(r.text)
	return strings.Contains(lower, "invalid password") || strings.Contains(lower, "invalid username-password")
}

func isDefaultUserNoPassError(r respReply) bool {
	return r.kind == '-' && strings.Contains(strings.ToLower(r.text), "without any password configured")
}

func isLegacyNoPasswordSetError(r respReply) bool {
	return r.kind == '-' && strings.Contains(strings.ToLower(r.text), "no password is set")
}

func isTwoArgAuthUnsupportedError(r respReply) bool {
	if r.kind != '-' {
		return false
	}
	lower := strings.ToLower(r.text)
	return strings.Contains(lower, "wrong number of arguments") || strings.Contains(lower, "syntax error")
}

func isServiceDeniedError(r respReply) bool {
	if r.kind != '-' {
		return false
	}
	if hasErrorPrefix(r.text, "DENIED") {
		return true
	}
	return strings.Contains(strings.ToLower(r.text), "max number of clients")
}
