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

// Package rdp provides a Goonami weak-credentials and blank-password detector
// ("dt/wk/rdp") for Remote Desktop Protocol (RDP) services.
package rdp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/rdpclient"
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
	// ModuleName is the unique detector module name for RDP weak credentials.
	ModuleName = "dt/wk/rdp"

	maxConsecutiveTransportErrors = 3

	probeUser     = "goonami-rdp-probe"
	probePassword = "goonami-rdp-invalid-probe-password"
)

func init() {
	module.RegisterDetector(ModuleName, New)
}

// DefaultCredentials returns the curated high-signal RDP credential pairs
// (including empty passwords for each common account and an empty pair for
// unauthenticated desktop logon) ordered for fast, lockout-conscious scanning.
func DefaultCredentials() []bruteforce.Credential {
	return []bruteforce.Credential{
		{Username: "", Password: ""},
		{Username: "Administrator", Password: ""},
		{Username: "Administrator", Password: "Administrator"},
		{Username: "Administrator", Password: "password"},
		{Username: "Administrator", Password: "Password1"},
		{Username: "Administrator", Password: "Password123"},
		{Username: "Administrator", Password: "admin"},
		{Username: "Administrator", Password: "123456"},
		{Username: "admin", Password: ""},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "Password1"},
		{Username: "admin", Password: "123456"},
		{Username: "user", Password: ""},
		{Username: "user", Password: "user"},
		{Username: "user", Password: "password"},
		{Username: "user", Password: "123456"},
		{Username: "root", Password: ""},
		{Username: "root", Password: "root"},
		{Username: "root", Password: "password"},
		{Username: "guest", Password: ""},
		{Username: "guest", Password: "guest"},
		{Username: "test", Password: ""},
		{Username: "test", Password: "test"},
		{Username: "test", Password: "password"},
		{Username: "ubuntu", Password: ""},
		{Username: "ubuntu", Password: "ubuntu"},
		{Username: "ubuntu", Password: "password"},
		{Username: "vagrant", Password: ""},
		{Username: "vagrant", Password: "vagrant"},
	}
}

// New creates a new RDP weak-credentials detector backed by the generic
// brute-force library and curated RDP default credentials.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return NewWithOptions(ctx, cfg, nil)
}

// NewWithOptions creates a new RDP weak-credentials detector with custom
// brute-force options. When opts is nil, a curated RDP credential store
// containing DefaultCredentials is used.
func NewWithOptions(ctx context.Context, cfg *config.Config, opts *bruteforce.Options) (*bruteforce.Detector, error) {
	if opts == nil {
		store := credentialstore.New()
		for _, cred := range DefaultCredentials() {
			if err := store.AddUser(cred.Username); err != nil {
				return nil, err
			}
			if err := store.AddPasswordForUser(cred.Username, cred.Password); err != nil {
				return nil, err
			}
		}
		opts = &bruteforce.Options{
			CredentialStore: store,
		}
	}
	return bruteforce.New(ctx, cfg, NewHandler(cfg), opts)
}

// Handler implements bruteforce.Handler for RDP authentication probing and
// credential verification.
type Handler struct {
	client *rdpclient.Client

	mu           sync.RWMutex
	modes        map[string]rdpclient.AuthMode
	skippedUsers map[string]map[string]bool
}

// NewHandler creates a new RDP brute-force handler using the given config.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		client:       rdpclient.New(cfg),
		modes:        make(map[string]rdpclient.AuthMode),
		skippedUsers: make(map[string]map[string]bool),
	}
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return ModuleName
}

// Vulnerability returns the base vulnerability metadata reported when weak or
// blank RDP credentials are discovered.
func (h *Handler) Vulnerability() *vulnerabilitypb.Vulnerability {
	return vulnerabilitypb.Vulnerability_builder{
		MainId: vulnerabilitypb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "WEAK_CREDENTIALS_FOR_RDP",
		}.Build(),
		Severity:       vulnerabilitypb.Severity_CRITICAL,
		Title:          "Weak 'rdp' service credential",
		Description:    "Well known, weak, or empty credentials are detected for 'rdp' service.",
		Recommendation: "Enforce Network Level Authentication (NLA/CredSSP), disallow blank passwords, and set strong unique passwords for all RDP accounts.",
	}.Build()
}

type rdpWorker struct {
	handler           *Handler
	consecutiveErrors int
}

// NewWorker returns a Worker for testing RDP credentials sequentially.
func (h *Handler) NewWorker() bruteforce.Worker {
	return &rdpWorker{handler: h}
}

// Close releases resources held by the worker.
func (w *rdpWorker) Close() error {
	return nil
}

func resolveAddr(service *networkservicepb.NetworkService) (string, bool, error) {
	authorities, err := netendpoint.ToURIAuthorities(service.GetNetworkEndpoint())
	if err != nil {
		return "", false, err
	}
	var fallback string
	for _, auth := range authorities {
		host, _, splitErr := net.SplitHostPort(auth)
		if splitErr != nil {
			continue
		}
		if net.ParseIP(host) != nil {
			return auth, true, nil
		}
		fallback = auth
	}
	if fallback != "" {
		return fallback, true, nil
	}
	return "", false, nil
}

func (h *Handler) setMode(addr string, mode rdpclient.AuthMode) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.modes[addr] = mode
	delete(h.skippedUsers, addr)
}

func (h *Handler) modeFor(addr string) rdpclient.AuthMode {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if m, ok := h.modes[addr]; ok {
		return m
	}
	return rdpclient.AuthModeCredSSP
}

func (h *Handler) markUserSkipped(addr, username string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.skippedUsers[addr] == nil {
		h.skippedUsers[addr] = make(map[string]bool)
	}
	h.skippedUsers[addr][strings.ToLower(username)] = true
}

func (h *Handler) isUserSkipped(addr, username string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.skippedUsers[addr][strings.ToLower(username)]
}

// Fingerprint verifies whether the target network service is an RDP server
// supporting deterministic credential or passwordless verification.
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

	addr, hasPort, err := resolveAddr(service)
	if err != nil {
		return false, err
	}
	if !hasPort {
		return false, nil
	}

	probe, err := h.client.Probe(ctx, addr, probeUser, probePassword)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "RDP fingerprint probe skipped %q: %v", addr, err) // NOMUTANTS -- diagnostic logging
		return false, nil
	}

	h.setMode(addr, probe.Mode)
	return true, nil
}

// TestCredential attempts to authenticate against the fingerprinted RDP
// service using cred.
func (h *Handler) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	addr, hasPort, err := resolveAddr(service)
	if err != nil {
		return false, err
	}
	if !hasPort {
		return false, fmt.Errorf("%w: RDP endpoint missing port", bruteforce.ErrStopBruteForce)
	}

	mode := h.modeFor(addr)
	if mode != rdpclient.AuthModeNoAuth && cred.Username == "" {
		return false, nil
	}
	if h.isUserSkipped(addr, cred.Username) {
		return false, nil
	}

	err = h.client.Authenticate(ctx, addr, mode, cred.Username, cred.Password)
	if err == nil {
		return true, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if errors.Is(err, rdpclient.ErrAccountUnavailable) {
		log.DebugContextf(ctx, log.DebugLevelService, "skipping remaining RDP attempts for unavailable account %q: %v", cred.Username, err) // NOMUTANTS -- diagnostic logging
		h.markUserSkipped(addr, cred.Username)
		return false, nil
	}
	if errors.Is(err, rdpclient.ErrAuthFailed) {
		return false, nil
	}
	if errors.Is(err, rdpclient.ErrAuthUnsupported) {
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
	}
	return false, err
}

func (w *rdpWorker) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
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
		log.DebugContextf(ctx, log.DebugLevelService, "stopping RDP brute force after %d consecutive transport errors: %v", w.consecutiveErrors, err) // NOMUTANTS -- diagnostic logging
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
	}
	log.DebugContextf(ctx, log.DebugLevelRequest, "RDP authentication attempt for %q failed with transport error: %v", cred.Username, err) // NOMUTANTS -- diagnostic logging
	return false, nil
}
