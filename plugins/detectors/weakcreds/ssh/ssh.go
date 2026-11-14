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

// Package ssh provides a Goonami weak credentials detector ("dt/wk/ssh") for
// SSH services by migrating Tsunami's NcrackCredentialTester SSH support.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/sshclient"
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
	moduleName = "dt/wk/ssh"

	maxConsecutiveTransportErrors = 3

	// maxPenaltyCooldownRetries bounds cumulative pre-banner drop sleeps across
	// Fingerprint and all concurrent TestCredential workers on a single SSH
	// endpoint so OpenSSH 9.8+ PerSourcePenalties does not stall host scans.
	maxPenaltyCooldownRetries = 15

	// penaltyCooldownSleep is the backoff interval when OpenSSH 9.8+
	// PerSourcePenalties closes a TCP connection (with EOF or "Not allowed at
	// this time") before sending the SSH banner. Three 5s cooldown waves clear
	// OpenSSH's default 15s penalty_min window.
	penaltyCooldownSleep = 5 * time.Second

	probeUser      = "goonami-ssh-probe"
	probePassword  = "goonami-ssh-invalid-probe-password"
	canaryUser     = "goonami-invalid-user-9f8e7d"
	canaryPassword = "goonami-ssh-invalid-canary-9f8e7d6c"
)

type sshUserDefaults struct {
	username       string
	extraPasswords []string
}

var sshCuratedDefaults = []sshUserDefaults{
	{username: "root", extraPasswords: []string{"toor", "password"}},
	{username: "admin", extraPasswords: []string{"password"}},
	{username: "ubuntu", extraPasswords: []string{"password"}},
	{username: "user", extraPasswords: []string{"password", "123456"}},
	{username: "test", extraPasswords: []string{"password", "123456"}},
	{username: "alpine"},
	{username: "debian"},
	{username: "guest"},
	{username: "pi", extraPasswords: []string{"raspberry"}},
	{username: "vagrant"},
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New creates a new SSH weak credentials detector backed by the generic
// brute-force library.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return NewWithOptions(ctx, cfg, nil)
}

// NewWithOptions creates a new SSH weak credentials detector with custom
// brute-force options. When opts is nil, a curated SSH default credential store
// is initialized with common Linux/container SSH accounts, empty ("") and
// username-matching passwords, and service-specific default passwords.
func NewWithOptions(ctx context.Context, cfg *config.Config, opts *bruteforce.Options) (*bruteforce.Detector, error) {
	if cfg == nil {
		return nil, bruteforce.ErrConfigNil
	}
	if opts == nil {
		store, err := buildDefaultSSHStore()
		if err != nil {
			return nil, err
		}
		opts = &bruteforce.Options{
			CredentialStore: store,
		}
	}
	handler := newHandler(cfg)
	return bruteforce.New(ctx, cfg, handler, opts)
}

func buildDefaultSSHStore() (*credentialstore.CredentialStore, error) {
	store := credentialstore.New()
	for _, entry := range sshCuratedDefaults {
		if err := store.AddUser(entry.username); err != nil {
			return nil, err
		}
		if err := store.AddPasswordForUser(entry.username, ""); err != nil {
			return nil, err
		}
		if err := store.AddPasswordForUser(entry.username, entry.username); err != nil {
			return nil, err
		}
		for _, pass := range entry.extraPasswords {
			if err := store.AddPasswordForUser(entry.username, pass); err != nil {
				return nil, err
			}
		}
	}
	return store, nil
}

// endpointPenaltyState coordinates pre-banner penalty cooldown waves across
// concurrent brute-force workers targeting the same SSH endpoint. s.mu is
// intentionally held across sleepFn in waitOrSleep so concurrent workers wait
// out the active penalty wave (blocking in currentEpoch or waitOrSleep) rather
// than dialing mid-cooldown or burning multiple retry-budget slots for the same
// drop window.
type endpointPenaltyState struct {
	mu        sync.Mutex
	epoch     uint64
	remaining int
}

func (s *endpointPenaltyState) currentEpoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

func (s *endpointPenaltyState) waitOrSleep(ctx context.Context, seenEpoch uint64, sleepFn func(context.Context, time.Duration) error) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch > seenEpoch {
		// Another concurrent worker already slept through this penalty wave while
		// we waited on s.mu; retry immediately without burning another budget slot.
		return true, ctx.Err()
	}
	if s.remaining <= 0 {
		return false, nil
	}
	s.remaining--
	if err := sleepFn(ctx, penaltyCooldownSleep); err != nil {
		return false, err
	}
	s.epoch++
	return true, nil
}

// Handler implements bruteforce.Handler for SSH password and
// keyboard-interactive authentication.
type Handler struct {
	client  *sshclient.Client
	sleepFn func(context.Context, time.Duration) error

	mu            sync.Mutex
	penaltyStates map[string]*endpointPenaltyState
}

func newHandler(cfg *config.Config) *Handler {
	return &Handler{
		client:        sshclient.New(cfg),
		sleepFn:       sshclient.SleepContext,
		penaltyStates: make(map[string]*endpointPenaltyState),
	}
}

func (h *Handler) sleep(ctx context.Context, d time.Duration) error {
	if h.sleepFn != nil {
		return h.sleepFn(ctx, d)
	}
	return sshclient.SleepContext(ctx, d)
}

func (h *Handler) publishPenaltyState(addr string, candidate *endpointPenaltyState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.penaltyStates == nil {
		h.penaltyStates = make(map[string]*endpointPenaltyState)
	}
	if _, exists := h.penaltyStates[addr]; !exists {
		h.penaltyStates[addr] = candidate
	}
}

func (h *Handler) getPenaltyState(addr string) *endpointPenaltyState {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.penaltyStates == nil {
		h.penaltyStates = make(map[string]*endpointPenaltyState)
	}
	st, ok := h.penaltyStates[addr]
	if !ok {
		st = &endpointPenaltyState{remaining: maxPenaltyCooldownRetries}
		h.penaltyStates[addr] = st
	}
	return st
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return moduleName
}

type sshWorker struct {
	handler           *Handler
	consecutiveErrors int
}

// NewWorker returns a Worker for testing SSH credentials sequentially.
func (h *Handler) NewWorker() bruteforce.Worker {
	return &sshWorker{handler: h}
}

func (w *sshWorker) Close() error {
	return nil
}

func (w *sshWorker) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
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
		log.DebugContextf(ctx, log.DebugLevelService, "stopping SSH brute force after %d consecutive transport errors: %v", w.consecutiveErrors, err)
		return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
	}
	log.DebugContextf(ctx, log.DebugLevelRequest, "SSH authentication attempt for %q failed: %v", cred.Username, err)
	return false, nil
}

// Close releases resources held by the handler.
func (h *Handler) Close() error {
	h.mu.Lock()
	clear(h.penaltyStates)
	h.mu.Unlock()
	return nil
}

// Vulnerability returns the base vulnerability metadata reported when weak SSH
// credentials are discovered.
func (h *Handler) Vulnerability() *vulnerabilitypb.Vulnerability {
	return vulnerabilitypb.Vulnerability_builder{
		MainId: vulnerabilitypb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "WEAK_CREDENTIALS_FOR_SSH",
		}.Build(),
		Severity:       vulnerabilitypb.Severity_CRITICAL,
		Title:          "Weak 'ssh' service credential",
		Description:    "Well known or weak credentials are detected for 'ssh' service.",
		Recommendation: "Change the password of all affected users to a strong one.",
	}.Build()
}

// Fingerprint verifies whether the target network service is an SSH server that
// supports password authentication before attempting credential brute-forcing.
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

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	state := &endpointPenaltyState{remaining: maxPenaltyCooldownRetries}
	accepted, err := h.connectWithPenaltyRetry(ctx, addr, probeUser, probePassword, state)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		log.DebugContextf(ctx, log.DebugLevelService, "SSH fingerprint probe failed for %q: %v", addr, err)
		return false, nil
	}
	if accepted {
		log.DebugContextf(ctx, log.DebugLevelService, "SSH fingerprint probe succeeded for invalid user on %q; skipping accept-all SSH honeypot", addr)
		return false, nil
	}
	h.publishPenaltyState(addr, state)
	return true, nil
}

// TestCredential attempts to authenticate against the SSH service using the
// provided credential, verifying any positive match against negative canary
// controls to rule out global and per-account wildcard SSH honeypots.
func (h *Handler) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	state := h.getPenaltyState(addr)
	matched, err := h.connectWithPenaltyRetry(ctx, addr, cred.Username, cred.Password, state)
	if err != nil || !matched {
		return false, err
	}

	// Negative control 1: verify that a distinct <=256-byte invalid canary
	// password for the same account is rejected (rules out Cowrie per-user
	// wildcard entries such as "root:x:*").
	wildcardAccepted, err := h.connectWithPenaltyRetry(ctx, addr, cred.Username, canaryPassword, state)
	if err != nil {
		return false, err
	}
	if wildcardAccepted {
		log.DebugContextf(ctx, log.DebugLevelService, "SSH target %q accepted invalid canary password for %q; skipping wildcard honeypot account", addr, cred.Username)
		return false, nil
	}

	// Negative control 2: when an empty password ("") matched, also verify that
	// a nonexistent canary username with "" is rejected (rules out global
	// RFC 4252 "none"-auth or empty-password honeypots).
	if cred.Password == "" {
		emptyWildcardAccepted, err := h.connectWithPenaltyRetry(ctx, addr, canaryUser, "", state)
		if err != nil {
			return false, err
		}
		if emptyWildcardAccepted {
			log.DebugContextf(ctx, log.DebugLevelService, "SSH target %q accepted empty password for invalid canary user; stopping scan on accept-all honeypot", addr)
			return false, fmt.Errorf("%w: accept-all empty-password SSH honeypot", bruteforce.ErrStopBruteForce)
		}
	}

	return true, nil
}

func (h *Handler) connectWithPenaltyRetry(ctx context.Context, addr, username, password string, state *endpointPenaltyState) (bool, error) {
	for {
		seenEpoch := state.currentEpoch()
		conn, err := h.client.Connect(ctx, addr, username, password)
		if err == nil {
			_ = conn.Close()
			return true, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if errors.Is(err, sshclient.ErrAuthFailed) {
			return false, nil
		}
		if errors.Is(err, sshclient.ErrPasswordAuthUnsupported) {
			return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
		}
		if errors.Is(err, sshclient.ErrConnectionDropped) && h.client.HasConfirmedSSH(addr) {
			slept, sleepErr := state.waitOrSleep(ctx, seenEpoch, h.sleep)
			if sleepErr != nil {
				return false, sleepErr
			}
			if !slept {
				log.DebugContextf(ctx, log.DebugLevelService, "exhausted SSH pre-banner penalty cooldown retries on %q", addr)
				return false, fmt.Errorf("%w: %w", bruteforce.ErrStopBruteForce, err)
			}
			continue
		}
		return false, err
	}
}
