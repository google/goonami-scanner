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

	maxRecordedPreBannerBytes = 256
)

var (
	// ErrPasswordAuthUnsupported indicates the SSH server does not support password authentication.
	ErrPasswordAuthUnsupported = errors.New("ssh: password authentication unsupported")

	// ErrNotSSHService indicates the target network service is not a valid SSH service.
	ErrNotSSHService = errors.New("ssh: target is not an SSH service")

	// ErrConnectionDropped indicates the TCP connection was accepted and closed before any SSH
	// version banner was received (such as OpenSSH PerSourcePenalties or MaxStartups drops).
	ErrConnectionDropped = errors.New("ssh: connection dropped before banner")

	// ErrAuthFailed indicates the credentials were rejected by the SSH server.
	ErrAuthFailed = errors.New("ssh: authentication failed")
)

// Client manages SSH connection establishment and password authentication.
type Client struct {
	coreConfig *config.Config
	config     *sccpb.SSHClientConfig
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
	}
}

// Timeout returns the configured connection and authentication timeout duration.
func (c *Client) Timeout() time.Duration {
	if c.config.GetTimeoutSeconds() > 0 {
		return time.Duration(c.config.GetTimeoutSeconds()) * time.Second
	}
	return DefaultTimeout
}

func (c *Client) dial(ctx context.Context, addr, bannerPrefix string, clientConfig *ssh.ClientConfig) (*ssh.Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			log.DebugContextf(ctx, log.DebugLevelRequest, "closed connection on context cancellation: %v", closeErr) // NOMUTANTS -- diagnostic logging only
		}
	})
	defer stop()

	bc := &bannerConn{
		Conn:         conn,
		bannerPrefix: bannerPrefix,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(bc, addr, clientConfig)
	if err != nil {
		if bc.bannerErr != nil {
			return nil, bc.bannerErr
		}
		if bc.isPreBannerDrop(ctx, err) {
			return nil, fmt.Errorf("%w: %w: %w", ErrNotSSHService, ErrConnectionDropped, err)
		}
		if ctx.Err() == nil && errors.Is(err, net.ErrClosed) {
			return nil, fmt.Errorf("%w: %w", ErrNotSSHService, err)
		}
		return nil, err
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

type bannerConn struct {
	net.Conn
	bannerPrefix string
	lineBuf      []byte
	preBanner    []byte
	bannerSeen   bool
	bannerErr    error
}

func (bc *bannerConn) Read(p []byte) (int, error) {
	n, err := bc.Conn.Read(p)
	if bc.bannerSeen {
		return n, err
	}
	for _, b := range p[:n] {
		if len(bc.preBanner) < maxRecordedPreBannerBytes { // NOMUTANTS -- defensive memory cap against oversized non-SSH responses
			bc.preBanner = append(bc.preBanner, b)
		}
		if b == '\n' {
			line := strings.TrimSuffix(string(bc.lineBuf), "\r")
			bc.lineBuf = bc.lineBuf[:0]
			if strings.HasPrefix(line, "SSH-") {
				bc.bannerSeen = true
				if bc.bannerPrefix != "" && !strings.HasPrefix(line, bc.bannerPrefix) {
					bc.bannerErr = fmt.Errorf("%w: server banner %q does not match prefix %q", ErrNotSSHService, line, bc.bannerPrefix)
					_ = bc.Conn.Close() // NOMUTANTS -- defensive socket close on early banner abort
					return 0, bc.bannerErr
				}
				break
			}
			continue
		}
		if len(bc.lineBuf) < maxRecordedPreBannerBytes { // NOMUTANTS -- defensive memory cap against oversized non-SSH responses
			bc.lineBuf = append(bc.lineBuf, b)
		}
	}
	return n, err
}

func (bc *bannerConn) isPreBannerDrop(ctx context.Context, err error) bool {
	if bc.bannerSeen || ctx.Err() != nil || !isConnectionDropError(err) {
		return false
	}
	s := string(bc.preBanner)
	return len(s) == 0 ||
		strings.HasPrefix(s, "Not allowed at this time") ||
		strings.HasPrefix(s, "Exceeded MaxStartups")
}

func isConnectionDropError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(strings.ToLower(err.Error()), "connection reset by peer")
}

// Connect attempts SSH password authentication with the given username and password.
// On success, it returns an established *ssh.Client connection (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, or ErrNotSSHService) wrapping the underlying SSH error.
func (c *Client) Connect(ctx context.Context, addr, username, password string) (*ssh.Client, error) {
	return c.ConnectWithPasswords(ctx, addr, username, password)
}

// ConnectWithPasswords attempts SSH password authentication with the given username by trying
// the provided passwords sequentially within a single SSH connection handshake.
// On success, it returns an established *ssh.Client connection (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, or ErrNotSSHService) wrapping the underlying SSH error.
func (c *Client) ConnectWithPasswords(ctx context.Context, addr, username string, passwords ...string) (*ssh.Client, error) {
	return c.ConnectWithBannerPrefix(ctx, addr, username, "", passwords...)
}

// ConnectWithBannerPrefix attempts SSH password authentication with the given username by trying
// the provided passwords sequentially within a single SSH connection handshake, requiring the
// server's SSH identification string to start with bannerPrefix when bannerPrefix is non-empty.
// If the server banner does not match bannerPrefix, the handshake aborts before key exchange and
// returns ErrNotSSHService. If the TCP connection is dropped before any SSH banner is received,
// the returned error wraps both ErrNotSSHService and ErrConnectionDropped.
func (c *Client) ConnectWithBannerPrefix(ctx context.Context, addr, username, bannerPrefix string, passwords ...string) (*ssh.Client, error) {
	ctx = log.ContextForModule(ctx, "clients/sshclient") // NOMUTANTS -- diagnostic logging context only

	timeout := c.Timeout()
	connCtx, cancel := context.WithTimeout(ctx, timeout) // NOMUTANTS -- defensive per-connection timeout bound
	defer cancel()

	attempt := 0
	clientConfig := &ssh.ClientConfig{
		User: username,
		AuthCallback: func(authCtx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if !slices.Contains(authCtx.AllowedMethods, "password") {
				return nil, ErrPasswordAuthUnsupported
			}
			if attempt >= len(passwords) {
				return nil, ErrAuthFailed
			}
			password := passwords[attempt]
			attempt++
			return ssh.Password(password), nil
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, err := c.dial(connCtx, addr, bannerPrefix, clientConfig)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "SSH connection/authentication to %s for user %q failed: %v", addr, username, err) // NOMUTANTS -- diagnostic logging only
		return nil, ClassifyError(err)
	}
	return client, nil
}

// ClassifyError maps standard network and SSH errors into canonical sentinels wrapping the original error.
func ClassifyError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrPasswordAuthUnsupported) || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrNotSSHService) {
		return err
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrNotSSHService, err)
	}

	msg := strings.ToLower(err.Error())

	if strings.Contains(msg, "attempted methods [none]") {
		return fmt.Errorf("%w: %w", ErrPasswordAuthUnsupported, err)
	}

	if strings.Contains(msg, "attempted methods") && strings.Contains(msg, "password") {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	if strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "password auth failed") ||
		strings.Contains(msg, "failed authentication") ||
		strings.Contains(msg, "authentication failed") ||
		strings.Contains(msg, "auth failed") ||
		strings.Contains(msg, "too many authentication failures") {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	if strings.Contains(msg, "no version identifier") ||
		strings.Contains(msg, "banner header contains illegal") ||
		strings.Contains(msg, "overflow reading version") ||
		strings.Contains(msg, "no common algorithm") ||
		strings.Contains(msg, "protocol version") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "eof") {
		return fmt.Errorf("%w: %w", ErrNotSSHService, err)
	}

	return err
}
