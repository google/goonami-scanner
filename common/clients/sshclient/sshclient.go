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
)

var (
	// ErrPasswordAuthUnsupported indicates the SSH server does not support password authentication.
	ErrPasswordAuthUnsupported = errors.New("ssh: password authentication unsupported")

	// ErrNotSSHService indicates the target network service is not a valid SSH service.
	ErrNotSSHService = errors.New("ssh: target is not an SSH service")

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

// Connect attempts SSH password authentication with the given username and password.
// On success, it returns an established *ssh.Client connection (which the caller is responsible
// for closing). On failure, it returns a classified sentinel error (such as ErrAuthFailed,
// ErrPasswordAuthUnsupported, or ErrNotSSHService) wrapping the underlying SSH error.
func (c *Client) Connect(ctx context.Context, addr, username, password string) (*ssh.Client, error) {
	ctx = log.ContextForModule(ctx, "clients/sshclient")

	timeout := c.Timeout()
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	triedPassword := false
	clientConfig := &ssh.ClientConfig{
		User: username,
		AuthCallback: func(authCtx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if !slices.Contains(authCtx.AllowedMethods, "password") {
				return nil, ErrPasswordAuthUnsupported
			}
			if triedPassword {
				return nil, ErrAuthFailed
			}
			triedPassword = true
			return ssh.Password(password), nil
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, err := c.dial(connCtx, addr, clientConfig)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "SSH connection/authentication to %s for user %q failed: %v", addr, username, err)
		return nil, ClassifyError(err)
	}
	return client, nil
}

// ClassifyError maps standard network and SSH errors into canonical sentinels wrapping the original error.
func ClassifyError(err error) error {
	if err == nil {
		return nil
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
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "eof") {
		return fmt.Errorf("%w: %w", ErrNotSSHService, err)
	}

	return err
}
