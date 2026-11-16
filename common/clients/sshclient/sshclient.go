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

// Package sshclient provides a reusable SSH client for network service probing,
// password authentication, and sentinel error classification.
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"weak"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	sccpb "github.com/google/goonami-scanner/common/clients/sshclient/ssh_client_config_go_proto"
)

const (
	// DefaultTimeout is the default timeout for SSH connections and authentication.
	DefaultTimeout = time.Duration(sccpb.Default_SSHClientConfig_TimeoutSeconds) * time.Second

	// maxKeyboardInteractiveEmptyPrompts bounds consecutive or total zero-prompt
	// informational challenges accepted in a single keyboard-interactive attempt.
	maxKeyboardInteractiveEmptyPrompts = 3

	maxBannerPreambleLines = 16
	maxBannerLineBytes     = 512
)

var (
	// ErrPasswordAuthUnsupported indicates the SSH server does not support password
	// or keyboard-interactive authentication.
	ErrPasswordAuthUnsupported = errors.New("ssh: password authentication unsupported")

	// ErrNotSSHService indicates the target network service is not a valid SSH service.
	ErrNotSSHService = errors.New("ssh: target is not an SSH service")

	// ErrConnectionDropped indicates that an established TCP connection was closed
	// or reset by the peer before sending any SSH protocol banner bytes (for example,
	// during OpenSSH 9.8+ PerSourcePenalties or MaxStartups rate-limiting). It is
	// always wrapped alongside ErrNotSSHService for backward compatibility.
	ErrConnectionDropped = errors.New("ssh: connection closed before banner")

	// ErrAuthFailed indicates the credentials were rejected by the SSH server.
	ErrAuthFailed = errors.New("ssh: authentication failed")

	// confirmedSSHByConfig shares wire-confirmed SSH endpoints across independent
	// SSH detector plugins initialized with the same scan *config.Config without
	// retaining strong references once a scan *config.Config becomes unreachable.
	confirmedSSHMu       sync.RWMutex
	confirmedSSHByConfig = make(map[weak.Pointer[config.Config]]*confirmedSSHSet)
)

type confirmedSSHSet struct {
	mu    sync.RWMutex
	addrs map[string]bool
}

func (s *confirmedSSHSet) has(addr string) bool {
	if addr == "" {
		return false
	}
	s.mu.RLock()
	ok := s.addrs[addr]
	s.mu.RUnlock()
	return ok
}

func (s *confirmedSSHSet) add(addr string) {
	if addr == "" || s.has(addr) {
		return
	}
	s.mu.Lock()
	if s.addrs == nil {
		s.addrs = make(map[string]bool)
	}
	s.addrs[addr] = true
	s.mu.Unlock()
}

func confirmedSetForConfig(cfg *config.Config) *confirmedSSHSet {
	if cfg == nil {
		return &confirmedSSHSet{}
	}
	wp := weak.Make(cfg)
	confirmedSSHMu.RLock()
	set, ok := confirmedSSHByConfig[wp]
	confirmedSSHMu.RUnlock()
	if ok {
		return set
	}

	confirmedSSHMu.Lock()
	defer confirmedSSHMu.Unlock()
	set, ok = confirmedSSHByConfig[wp]
	if !ok {
		set = &confirmedSSHSet{}
		confirmedSSHByConfig[wp] = set
		runtime.AddCleanup(cfg, deleteConfirmedSSHEndpoints, wp)
	}
	return set
}

func deleteConfirmedSSHEndpoints(wp weak.Pointer[config.Config]) {
	confirmedSSHMu.Lock()
	delete(confirmedSSHByConfig, wp)
	confirmedSSHMu.Unlock()
}

// SleepContext pauses execution for duration d or returns ctx.Err() immediately
// if ctx is canceled before d elapses.
func SleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Client manages SSH connection establishment and password authentication.
type Client struct {
	coreConfig *config.Config
	config     *sccpb.SSHClientConfig
	confirmed  *confirmedSSHSet
}

// New creates a new SSH Client populated from configuration.
func New(cfg *config.Config) *Client {
	sshCfg := &sccpb.SSHClientConfig{}
	if cfg != nil {
		if cfg.ClientsConfig().HasSsh() {
			proto.Merge(sshCfg, cfg.ClientsConfig().GetSsh())
		}
		if !sshCfg.HasTimeoutSeconds() {
			if timeout := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); timeout > 0 {
				sshCfg.SetTimeoutSeconds(timeout)
			}
		}
	}

	return &Client{
		coreConfig: cfg,
		config:     sshCfg,
		confirmed:  confirmedSetForConfig(cfg),
	}
}

// Timeout returns the configured connection and authentication timeout duration.
func (c *Client) Timeout() time.Duration {
	if c.config.GetTimeoutSeconds() > 0 {
		return time.Duration(c.config.GetTimeoutSeconds()) * time.Second
	}
	return DefaultTimeout
}

// HasConfirmedSSH reports whether an SSH protocol banner ("SSH-*") or OpenSSH
// pre-banner rate-limit notice has been observed from addr by this Client (or,
// when New was called with a non-nil *config.Config, by any Client sharing that
// *config.Config; nil-config Clients isolate confirmation state per Client).
func (c *Client) HasConfirmedSSH(addr string) bool {
	if c.confirmed == nil {
		return false
	}
	return c.confirmed.has(addr)
}

func (c *Client) recordConfirmedSSH(addr string) {
	if c.confirmed != nil {
		c.confirmed.add(addr)
	}
}

type bannerCaptureConn struct {
	net.Conn
	mu              sync.Mutex
	bytesRead       int
	linesSeen       int
	lineBuf         []byte
	serverVersion   string
	rateLimitBanner bool
	bannerDone      bool
}

func (b *bannerCaptureConn) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	if n > 0 {
		b.mu.Lock()
		b.bytesRead += n
		if !b.bannerDone {
			b.consumeBannerBytes(p[:n])
		}
		b.mu.Unlock()
	}
	return n, err
}

func (b *bannerCaptureConn) consumeBannerBytes(chunk []byte) {
	for len(chunk) > 0 && !b.bannerDone {
		nlIdx := bytes.IndexByte(chunk, '\n')
		part := chunk
		if nlIdx >= 0 {
			part = chunk[:nlIdx]
		}
		if remaining := maxBannerLineBytes - len(b.lineBuf); remaining > 0 {
			b.lineBuf = append(b.lineBuf, part[:min(len(part), remaining)]...)
		}
		if nlIdx < 0 {
			return
		}
		chunk = chunk[nlIdx+1:]

		line := strings.TrimSuffix(string(b.lineBuf), "\r")
		b.lineBuf = b.lineBuf[:0]
		b.linesSeen++
		if strings.HasPrefix(line, "SSH-") {
			b.serverVersion = line
			b.bannerDone = true
			return
		}
		if isOpenSSHRateLimitBanner(line) {
			b.rateLimitBanner = true
		}
		if b.linesSeen >= maxBannerPreambleLines {
			b.bannerDone = true
			return
		}
	}
}

func isOpenSSHRateLimitBanner(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.EqualFold(trimmed, "Not allowed at this time") ||
		strings.EqualFold(trimmed, "Exceeded MaxStartups")
}

func (b *bannerCaptureConn) snapshot() (bytesRead int, serverVersion string, rateLimitBanner bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytesRead, b.serverVersion, b.rateLimitBanner
}

func (c *Client) dial(ctx context.Context, addr string, clientConfig *ssh.ClientConfig) (*ssh.Client, string, bool, error) {
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		droppedPreBanner := ctx.Err() == nil && isPreBannerDropError(err)
		return nil, "", droppedPreBanner, err
	}

	trackedConn := &bannerCaptureConn{Conn: rawConn}
	stop := context.AfterFunc(ctx, func() {
		if closeErr := rawConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			log.DebugContextf(ctx, log.DebugLevelRequest, "closed connection on context cancellation: %v", closeErr)
		}
	})
	defer stop()

	sshConn, chans, reqs, err := ssh.NewClientConn(trackedConn, addr, clientConfig)
	bytesRead, capturedBanner, rateLimitBanner := trackedConn.snapshot()
	if err != nil {
		if strings.HasPrefix(capturedBanner, "SSH-") || rateLimitBanner {
			c.recordConfirmedSSH(addr)
		}
		droppedPreBanner := (bytesRead == 0 || rateLimitBanner) && ctx.Err() == nil && isPreBannerDropError(err)
		return nil, capturedBanner, droppedPreBanner, err
	}

	serverVersion := string(sshConn.ServerVersion())
	if serverVersion == "" {
		serverVersion = capturedBanner
	}
	if strings.HasPrefix(serverVersion, "SSH-") {
		c.recordConfirmedSSH(addr)
	}
	return ssh.NewClient(sshConn, chans, reqs), serverVersion, false, nil
}

// Connect attempts SSH password or keyboard-interactive authentication with the given username
// and password. On success, it returns an established *ssh.Client connection (which the caller is
// responsible for closing). On failure, it returns a classified sentinel error (such as
// ErrAuthFailed, ErrPasswordAuthUnsupported, ErrConnectionDropped, or ErrNotSSHService) wrapping
// the underlying SSH error.
func (c *Client) Connect(ctx context.Context, addr, username, password string) (*ssh.Client, error) {
	client, _, err := c.connectAndReturnServerVersion(ctx, addr, username, []string{password})
	return client, err
}

// ConnectWithPasswords attempts SSH password or keyboard-interactive authentication with the given
// username by trying the provided passwords sequentially within a single SSH connection handshake.
// On success, it returns an established *ssh.Client connection (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, ErrConnectionDropped, or ErrNotSSHService) wrapping the underlying
// SSH error.
func (c *Client) ConnectWithPasswords(ctx context.Context, addr, username string, passwords ...string) (*ssh.Client, error) {
	client, _, err := c.connectAndReturnServerVersion(ctx, addr, username, passwords)
	return client, err
}

// ConnectAndReturnServerVersion behaves like ConnectWithPasswords and additionally returns the
// peer's SSH identification banner (for example, "SSH-2.0-OpenSSH_9.9") whenever the banner
// exchange succeeded, even if authentication subsequently fails with ErrAuthFailed or
// ErrPasswordAuthUnsupported.
func (c *Client) ConnectAndReturnServerVersion(ctx context.Context, addr, username string, passwords ...string) (*ssh.Client, string, error) {
	return c.connectAndReturnServerVersion(ctx, addr, username, passwords)
}

func (c *Client) connectAndReturnServerVersion(ctx context.Context, addr, username string, passwords []string) (*ssh.Client, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	ctx = log.ContextForModule(ctx, "clients/sshclient")

	timeout := c.Timeout()
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	session := &passwordAuthSession{passwords: passwords}
	clientConfig := &ssh.ClientConfig{
		User:            username,
		AuthCallback:    session.authCallback,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, serverVersion, droppedPreBanner, err := c.dial(connCtx, addr, clientConfig)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, serverVersion, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "SSH connection/authentication to %s for user %q failed: %v", addr, username, err)
		if errors.Is(connCtx.Err(), context.DeadlineExceeded) {
			return nil, serverVersion, fmt.Errorf("%w: %w", ErrNotSSHService, err)
		}
		if droppedPreBanner {
			return nil, "", fmt.Errorf("%w: %w: %w", ErrNotSSHService, ErrConnectionDropped, err)
		}
		return nil, serverVersion, ClassifyError(err)
	}
	if session.acceptedUnchallengedNonEmptyPassword() {
		_ = client.Close()
		return nil, serverVersion, ErrAuthFailed
	}
	return client, serverVersion, nil
}

type passwordAuthSession struct {
	passwords       []string
	attempt         int
	abort           bool
	lastAttemptKbd  bool
	kbdPasswordSent bool
}

func (s *passwordAuthSession) authCallback(authCtx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if s.abort {
		return nil, ErrAuthFailed
	}
	hasPassword := slices.Contains(authCtx.AllowedMethods, "password")
	hasKeyboardInteractive := slices.Contains(authCtx.AllowedMethods, "keyboard-interactive")
	if !hasPassword && !hasKeyboardInteractive {
		if s.attempt == 0 {
			return nil, ErrPasswordAuthUnsupported
		}
		return nil, ErrAuthFailed
	}
	if s.attempt >= len(s.passwords) {
		return nil, ErrAuthFailed
	}
	password := s.passwords[s.attempt]
	s.attempt++
	s.lastAttemptKbd = !hasPassword
	s.kbdPasswordSent = false
	if hasPassword {
		return ssh.Password(password), nil
	}
	return s.keyboardInteractive(password), nil
}

func (s *passwordAuthSession) keyboardInteractive(password string) ssh.AuthMethod {
	emptyPrompts := 0
	return ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) == 0 {
			emptyPrompts++
			if emptyPrompts > maxKeyboardInteractiveEmptyPrompts {
				s.abort = true
				return nil, ErrAuthFailed
			}
			return nil, nil
		}
		if s.kbdPasswordSent || len(questions) != 1 {
			s.abort = true
			return nil, ErrAuthFailed
		}
		s.kbdPasswordSent = true
		return []string{password}, nil
	})
}

// acceptedUnchallengedNonEmptyPassword reports whether ssh.NewClientConn
// succeeded without challenging a candidate password while "" was absent from
// the remaining candidate slice—either because go_crypto/ssh's implicit
// pre-flight RFC 4252 "none" request succeeded (attempt == 0) or because a PAM
// keyboard-interactive server granted access after zero prompts
// (!kbdPasswordSent).
func (s *passwordAuthSession) acceptedUnchallengedNonEmptyPassword() bool {
	if s.attempt == 0 {
		return !slices.Contains(s.passwords, "")
	}
	return s.lastAttemptKbd && !s.kbdPasswordSent && !slices.Contains(s.passwords[s.attempt-1:], "")
}

func isPreBannerDropError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	if matchesAnyError(err, preBannerDropSentinels) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if msg == "eof" || strings.HasSuffix(msg, ": eof") || strings.Contains(msg, "unexpected eof") {
		return true
	}
	return containsAny(msg, preBannerDropSubstrings)
}

// ClassifyError maps standard network and SSH errors into canonical sentinels wrapping the original error.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrPasswordAuthUnsupported) || errors.Is(err, ErrNotSSHService) {
		return err
	}

	if matchesAnyError(err, notSSHServiceSentinels) {
		return fmt.Errorf("%w: %w", ErrNotSSHService, err)
	}

	msg := strings.ToLower(err.Error())

	if strings.Contains(msg, "attempted methods [none]") {
		return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
	}

	if strings.Contains(msg, "attempted methods") && (strings.Contains(msg, "password") || strings.Contains(msg, "keyboard-interactive")) {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if containsAny(msg, authFailedSubstrings) {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	if containsAny(msg, notSSHServiceSubstrings) {
		return fmt.Errorf("%w: %w", ErrNotSSHService, err)
	}

	return err
}

var (
	preBannerDropSentinels = []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		net.ErrClosed,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EPIPE,
	}
	preBannerDropSubstrings = []string{
		"connection reset",
		"forcibly closed",
		"broken pipe",
		"connection aborted",
		"closed network connection",
	}
	notSSHServiceSentinels = []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		net.ErrClosed,
		syscall.ECONNRESET,
		syscall.ECONNREFUSED,
		syscall.ECONNABORTED,
		syscall.EPIPE,
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.EHOSTDOWN,
		syscall.ETIMEDOUT,
	}
	authFailedSubstrings = []string{
		"unable to authenticate",
		"password auth failed",
		"failed authentication",
		"authentication failed",
		"auth failed",
		"too many authentication failures",
		"too many authentication attempts",
		"no more auth methods available",
	}
	notSSHServiceSubstrings = []string{
		// SSH banner, handshake, and framing/protocol errors from non-SSH or broken peers.
		"no version identifier",
		"banner header contains illegal",
		"junk character in version line",
		"overflow reading version",
		"no common algorithm",
		"protocol version",
		"first packet should be",
		"invalid packet length",
		"packet too small",
		"packet too large",
		"max packet length exceeded",
		"empty packet",
		"zero length packet",
		"illegal padding",
		"unexpected message type",
		"parse error in message type",
		"unmarshal error",
		"short read",
		"mac failure",
		"bogus newkeys",
		"unsupported cipher",
		"unsupported mac",
		"unexpected key exchange",
		"signature parse error",
		"invalid signature algorithm",
		"ssh: disconnect",
		// Network and transport errors indicating the endpoint is not an active SSH service.
		"connection reset",
		"forcibly closed",
		"broken pipe",
		"connection aborted",
		"connection refused",
		"no route to host",
		"network is unreachable",
		"host is down",
		"i/o timeout",
		"closed network connection",
		"eof",
	}
)

func matchesAnyError(err error, targets []error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
