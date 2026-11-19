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

package rdpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
)

const (
	// DefaultTimeout is the default per-attempt timeout for RDP connections and
	// authentication handshakes.
	DefaultTimeout = 5 * time.Second
)

var (
	// ErrAuthFailed indicates the RDP server rejected the provided credentials.
	ErrAuthFailed = errors.New("rdp: authentication failed")

	// ErrAccountUnavailable indicates the target account is locked out, disabled,
	// expired, or otherwise restricted, so further attempts for that account
	// should be skipped.
	ErrAccountUnavailable = errors.New("rdp: account locked, disabled, or restricted")

	// ErrAuthUnsupported indicates the target is an RDP server whose
	// authentication mode cannot be verified non-interactively without false
	// positives (for example, an interactive graphical login greeter or legacy
	// Standard RDP Security).
	ErrAuthUnsupported = errors.New("rdp: authentication mode unsupported")

	// ErrNotRDPService indicates the target could not be reached or does not
	// speak the RDP protocol.
	ErrNotRDPService = errors.New("rdp: target is not an RDP service")
)

// AuthMode identifies the verified RDP authentication mode detected during Probe.
type AuthMode int

const (
	// AuthModeUnknown indicates no verifiable RDP authentication mode was detected.
	AuthModeUnknown AuthMode = iota
	// AuthModeCredSSP indicates Network Level Authentication (CredSSP / NTLMv2).
	AuthModeCredSSP
	// AuthModeCredSSPSPNEGO indicates Network Level Authentication requiring
	// SPNEGO NegTokenInit / NegTokenResp encapsulation around NTLMv2.
	AuthModeCredSSPSPNEGO
	// AuthModeTLSInline indicates non-NLA TLS RDP performing inline TS_INFO_PACKET
	// credential authentication (confirmed by canary rejection).
	AuthModeTLSInline
	// AuthModeNoAuth indicates non-NLA TLS RDP that logs directly into a desktop
	// session (MS-RDPBCGR PDUTYPE2_SAVE_SESSION_INFO logon notification) without
	// requiring valid credentials.
	AuthModeNoAuth
)

// ProbeResult describes the RDP authentication capability discovered by Probe.
type ProbeResult struct {
	Mode AuthMode
}

// Client manages bounded RDP TCP/TLS connections, NLA/CredSSP authentication,
// and non-NLA TLS differential probing.
type Client struct {
	timeout time.Duration
}

// New creates a new RDP Client configured from cfg. When cfg is nil or sets no
// positive per-request timeout, DefaultTimeout is used.
func New(cfg *config.Config) *Client {
	timeout := DefaultTimeout
	if cfg != nil {
		if secs := cfg.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds(); secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	return &Client{timeout: timeout}
}

// Timeout returns the configured per-attempt timeout duration.
func (c *Client) Timeout() time.Duration {
	if c == nil || c.timeout <= 0 {
		return DefaultTimeout
	}
	return c.timeout
}

func (c *Client) dialAndNegotiate(ctx context.Context, addr string) (net.Conn, x224Result, func(), error) {
	timeout := c.Timeout()
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, x224Result{}, nil, ctx.Err()
		}
		return nil, x224Result{}, nil, fmt.Errorf("%w: %w", ErrNotRDPService, err)
	}

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) { // NOMUTANTS -- defensive socket deadline; context.AfterFunc also closes rawConn
		deadline = d // NOMUTANTS -- defensive socket deadline
	}
	_ = rawConn.SetDeadline(deadline) // NOMUTANTS -- defensive socket deadline

	stop := context.AfterFunc(ctx, func() {
		_ = rawConn.Close()
	})
	cleanup := func() {
		stop()
		_ = rawConn.Close()
	}

	res, err := x224Negotiate(rawConn, protocolSSL|protocolHybrid)
	if err != nil {
		cleanup() // NOMUTANTS -- defensive socket/AfterFunc cleanup on error
		if ctx.Err() != nil {
			return nil, x224Result{}, nil, ctx.Err()
		}
		return nil, x224Result{}, nil, err
	}
	return rawConn, res, cleanup, nil
}

func (c *Client) upgradeTLS(ctx context.Context, rawConn net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, // NOLINT
		// Cap at TLS 1.2 because Windows Server 2022/2025 Schannel CredSSP aborts
		// post-handshake with TLS Alert 80 (internal_error) over TLS 1.3.
		MaxVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close() // NOMUTANTS -- defensive socket cleanup on TLS handshake error
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: TLS handshake failed: %w", ErrNotRDPService, err)
	}
	return tlsConn, nil
}

// splitUserDomain separates "DOMAIN\\user" into (user, domain), normalizing
// local-account shorthand ".\\user" to an empty domain.
func splitUserDomain(username string) (string, string) {
	if idx := strings.IndexByte(username, '\\'); idx >= 0 {
		dom := username[:idx]
		if dom == "." {
			dom = ""
		}
		return username[idx+1:], dom
	}
	return username, ""
}

func targetHostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// Probe checks whether addr hosts an RDP service supporting deterministic
// credential verification (CredSSP/NLA, inline TLS authentication, or
// passwordless desktop logon) using a negative canary credential.
func (c *Client) Probe(ctx context.Context, addr, canaryUser, canaryPass string) (ProbeResult, error) {
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	ctx = log.ContextForModule(ctx, "clients/rdpclient") // NOMUTANTS -- diagnostic logging context

	probeCtx, cancel := context.WithTimeout(ctx, c.Timeout()) // NOMUTANTS -- defensive per-probe timeout bound
	defer cancel()                                            // NOMUTANTS -- defensive context timer cleanup

	rawConn, neg, cleanup, err := c.dialAndNegotiate(probeCtx, addr)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{}, err
	}
	defer cleanup() // NOMUTANTS -- defensive socket cleanup

	if neg.responseType == rdpNegFailure {
		return ProbeResult{}, fmt.Errorf("%w: RDP negotiation failure code 0x%08x", ErrAuthUnsupported, neg.failureCode)
	}

	switch neg.selectedProtocol {
	case protocolHybrid, protocolHybridEx:
		tlsConn, err := c.upgradeTLS(probeCtx, rawConn)
		if err != nil {
			if ctx.Err() != nil {
				return ProbeResult{}, ctx.Err()
			}
			return ProbeResult{}, err
		}
		targetHost := targetHostFromAddr(addr)
		user, domain := splitUserDomain(canaryUser)
		err = authenticateCredSSP(tlsConn, targetHost, user, canaryPass, domain, false)
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		if err == nil || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrAccountUnavailable) {
			return ProbeResult{Mode: AuthModeCredSSP}, nil
		}
		cleanup() // NOMUTANTS -- close initial socket before SPNEGO fallback dial
		if spnegoRes, spnegoErr := c.probeSPNEGOCredSSPFallback(probeCtx, addr, targetHost, user, canaryPass, domain); spnegoErr == nil {
			return spnegoRes, nil
		}
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{}, err

	case protocolSSL:
		tlsConn, err := c.upgradeTLS(probeCtx, rawConn)
		if err != nil {
			if ctx.Err() != nil {
				return ProbeResult{}, ctx.Err()
			}
			return ProbeResult{}, err
		}
		user, domain := splitUserDomain(canaryUser)
		outcome, err := runTLSExchange(tlsConn, user, canaryPass, domain)
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		if err != nil {
			return ProbeResult{}, err
		}
		switch outcome {
		case tlsOutcomeSaveSessionInfo:
			return ProbeResult{Mode: AuthModeNoAuth}, nil
		case tlsOutcomeRejected:
			return ProbeResult{Mode: AuthModeTLSInline}, nil
		case tlsOutcomeDesktopActive:
			// Server rendered a screen (e.g. Winlogon or xrdp interactive login box)
			// even for an invalid canary without sending SaveSessionInfo logon.
			return ProbeResult{}, fmt.Errorf("%w: non-NLA interactive login greeter", ErrAuthUnsupported)
		default:
			return ProbeResult{}, fmt.Errorf("%w: non-NLA RDP server did not reject canary", ErrAuthUnsupported)
		}

	default:
		return ProbeResult{}, fmt.Errorf("%w: unsupported RDP security protocol 0x%08x", ErrAuthUnsupported, neg.selectedProtocol)
	}
}

func (c *Client) probeSPNEGOCredSSPFallback(ctx context.Context, addr, targetHost, user, pass, domain string) (ProbeResult, error) {
	rawConn, neg, cleanup, err := c.dialAndNegotiate(ctx, addr)
	if err != nil {
		return ProbeResult{}, err
	}
	defer cleanup() // NOMUTANTS -- defensive socket cleanup
	if neg.responseType == rdpNegFailure || (neg.selectedProtocol != protocolHybrid && neg.selectedProtocol != protocolHybridEx) {
		return ProbeResult{}, ErrAuthUnsupported
	}
	tlsConn, err := c.upgradeTLS(ctx, rawConn)
	if err != nil {
		return ProbeResult{}, err
	}
	err = authenticateCredSSP(tlsConn, targetHost, user, pass, domain, true)
	if err == nil || errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrAccountUnavailable) {
		return ProbeResult{Mode: AuthModeCredSSPSPNEGO}, nil
	}
	return ProbeResult{}, err
}

// Authenticate tests a single credential pair against addr using the AuthMode
// discovered by Probe. Returning nil proves the credential is valid.
func (c *Client) Authenticate(ctx context.Context, addr string, mode AuthMode, username, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx = log.ContextForModule(ctx, "clients/rdpclient") // NOMUTANTS -- diagnostic logging context

	reqCtx, cancel := context.WithTimeout(ctx, c.Timeout()) // NOMUTANTS -- defensive per-request timeout bound
	defer cancel()                                          // NOMUTANTS -- defensive context timer cleanup

	rawConn, neg, cleanup, err := c.dialAndNegotiate(reqCtx, addr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer cleanup() // NOMUTANTS -- defensive socket cleanup

	if neg.responseType == rdpNegFailure {
		return fmt.Errorf("%w: RDP negotiation failure code 0x%08x", ErrAuthUnsupported, neg.failureCode)
	}

	user, domain := splitUserDomain(username)
	targetHost := targetHostFromAddr(addr)

	switch mode {
	case AuthModeCredSSP, AuthModeCredSSPSPNEGO:
		if neg.selectedProtocol != protocolHybrid && neg.selectedProtocol != protocolHybridEx {
			return fmt.Errorf("%w: expected NLA/CredSSP, got protocol 0x%08x", ErrAuthUnsupported, neg.selectedProtocol)
		}
		tlsConn, err := c.upgradeTLS(reqCtx, rawConn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		err = authenticateCredSSP(tlsConn, targetHost, user, password, domain, mode == AuthModeCredSSPSPNEGO)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err

	case AuthModeTLSInline:
		if neg.selectedProtocol != protocolSSL {
			return fmt.Errorf("%w: expected TLS RDP, got protocol 0x%08x", ErrAuthUnsupported, neg.selectedProtocol)
		}
		tlsConn, err := c.upgradeTLS(reqCtx, rawConn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		outcome, err := runTLSExchange(tlsConn, user, password, domain)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		if outcome == tlsOutcomeDesktopActive || outcome == tlsOutcomeSaveSessionInfo {
			return nil
		}
		if outcome == tlsOutcomeRejected {
			return ErrAuthFailed
		}
		return ErrAuthUnsupported

	case AuthModeNoAuth:
		if neg.selectedProtocol != protocolSSL {
			return fmt.Errorf("%w: expected TLS RDP, got protocol 0x%08x", ErrAuthUnsupported, neg.selectedProtocol)
		}
		tlsConn, err := c.upgradeTLS(reqCtx, rawConn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		outcome, err := runTLSExchange(tlsConn, user, password, domain)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		if outcome == tlsOutcomeSaveSessionInfo {
			return nil
		}
		return ErrAuthFailed

	default:
		return fmt.Errorf("%w: unknown RDP auth mode %d", ErrAuthUnsupported, mode)
	}
}
