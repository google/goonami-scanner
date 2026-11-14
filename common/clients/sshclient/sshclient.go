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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"syscall"
	"time"

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
)

var (
	// ErrPasswordAuthUnsupported indicates the SSH server does not support password
	// or keyboard-interactive authentication.
	ErrPasswordAuthUnsupported = errors.New("ssh: password authentication unsupported")

	// ErrNotSSHService indicates the target network service is not a valid SSH service.
	ErrNotSSHService = errors.New("ssh: target is not an SSH service")

	// ErrAuthFailed indicates the credentials were rejected by the SSH server.
	ErrAuthFailed = errors.New("ssh: authentication failed")
)

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
	config *sccpb.SSHClientConfig
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
		config: sshCfg,
	}
}

// Timeout returns the configured connection and authentication timeout duration.
func (c *Client) Timeout() time.Duration {
	if c.config.GetTimeoutSeconds() > 0 {
		return time.Duration(c.config.GetTimeoutSeconds()) * time.Second
	}
	return DefaultTimeout
}

func (c *Client) dial(ctx context.Context, addr string, clientConfig *ssh.ClientConfig) (*ssh.Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			log.DebugContextf(ctx, log.DebugLevelRequest, "closed connection on context cancellation: %v", closeErr)
		}
	})
	defer stop()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// Connect attempts SSH password or keyboard-interactive authentication with the given username
// and password. On success, it returns an established *ssh.Client connection (which the caller is
// responsible for closing). On failure, it returns a classified sentinel error (such as
// ErrAuthFailed, ErrPasswordAuthUnsupported, or ErrNotSSHService) wrapping the underlying SSH error.
func (c *Client) Connect(ctx context.Context, addr, username, password string) (*ssh.Client, error) {
	client, _, err := c.ConnectAndReturnServerVersion(ctx, addr, username, password)
	return client, err
}

// ConnectWithPasswords attempts SSH password or keyboard-interactive authentication with the given
// username by trying the provided passwords sequentially within a single SSH connection handshake.
// On success, it returns an established *ssh.Client connection (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, or ErrNotSSHService) wrapping the underlying SSH error.
func (c *Client) ConnectWithPasswords(ctx context.Context, addr, username string, passwords ...string) (*ssh.Client, error) {
	client, _, err := c.ConnectAndReturnServerVersion(ctx, addr, username, passwords...)
	return client, err
}

// ConnectAndReturnServerVersion behaves like ConnectWithPasswords and additionally returns the
// peer's SSH identification banner (for example, "SSH-2.0-OpenSSH_9.9") whenever the SSH handshake
// reached user authentication, even if authentication subsequently fails with ErrAuthFailed or
// ErrPasswordAuthUnsupported.
func (c *Client) ConnectAndReturnServerVersion(ctx context.Context, addr, username string, passwords ...string) (*ssh.Client, string, error) {
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

	client, err := c.dial(connCtx, addr, clientConfig)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, session.serverVersion, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "SSH connection/authentication to %s for user %q failed: %v", addr, username, err)
		if errors.Is(connCtx.Err(), context.DeadlineExceeded) {
			return nil, session.serverVersion, fmt.Errorf("%w: %w", ErrNotSSHService, err)
		}
		return nil, session.serverVersion, ClassifyError(err)
	}
	if v := string(client.ServerVersion()); v != "" {
		session.serverVersion = v
	}
	if session.acceptedUnchallengedNonEmptyPassword() {
		_ = client.Close()
		return nil, session.serverVersion, ErrAuthFailed
	}
	return client, session.serverVersion, nil
}

type passwordAuthSession struct {
	passwords          []string
	serverVersion      string
	attempt            int
	abort              bool
	passwordChallenged bool
}

func (s *passwordAuthSession) authCallback(authCtx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
	if authCtx.Metadata != nil {
		s.serverVersion = string(authCtx.Metadata.ServerVersion())
	}
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
	s.passwordChallenged = hasPassword
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
		if s.passwordChallenged || len(questions) != 1 {
			s.abort = true
			return nil, ErrAuthFailed
		}
		s.passwordChallenged = true
		return []string{password}, nil
	})
}

// acceptedUnchallengedNonEmptyPassword reports whether ssh.NewClientConn
// succeeded without challenging a candidate password while "" was absent from
// the remaining candidate slice—either because go_crypto/ssh's implicit
// pre-flight RFC 4252 "none" request succeeded (attempt == 0) or because a PAM
// keyboard-interactive server granted access after zero prompts
// (!passwordChallenged).
func (s *passwordAuthSession) acceptedUnchallengedNonEmptyPassword() bool {
	if s.passwordChallenged {
		return false
	}
	return !slices.Contains(s.passwords[max(0, s.attempt-1):], "")
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
