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
	"strings"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/sshclient"
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

	probeUser     = "goonami-ssh-probe"
	probePassword = "goonami-ssh-invalid-probe-password"
)

func init() {
	module.RegisterDetector(moduleName, New)
}

// New creates a new SSH weak credentials detector backed by the generic
// brute-force library.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return NewWithOptions(ctx, cfg, nil)
}

// NewWithOptions creates a new SSH weak credentials detector with custom
// brute-force options.
func NewWithOptions(ctx context.Context, cfg *config.Config, opts *bruteforce.Options) (*bruteforce.Detector, error) {
	handler := &Handler{
		client: sshclient.New(cfg),
	}
	return bruteforce.New(ctx, cfg, handler, opts)
}

// Handler implements bruteforce.Handler and bruteforce.Worker for SSH password
// authentication.
type Handler struct {
	client *sshclient.Client
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return moduleName
}

// NewWorker returns a Worker for testing credentials. Because Handler is
// stateless across attempts, it returns itself.
func (h *Handler) NewWorker() bruteforce.Worker {
	return h
}

// Close releases resources held by the worker.
func (h *Handler) Close() error {
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
	if !isCandidateServiceName(service.GetServiceName()) {
		return false, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	conn, err := h.client.Connect(ctx, addr, probeUser, probePassword)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		if errors.Is(err, sshclient.ErrAuthFailed) {
			return true, nil
		}
		log.DebugContextf(ctx, log.DebugLevelService, "SSH fingerprint probe failed for %q: %v", addr, err)
		return false, nil
	}
	_ = conn.Close()
	return true, nil
}

// TestCredential attempts to authenticate against the SSH service using the
// provided credential.
func (h *Handler) TestCredential(ctx context.Context, service *networkservicepb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	conn, err := h.client.Connect(ctx, addr, cred.Username, cred.Password)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "SSH authentication attempt for %q failed: %v", cred.Username, err)
		return false, nil
	}
	_ = conn.Close()
	return true, nil
}

func isCandidateServiceName(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "unknown", "ssh":
		return true
	default:
		return false
	}
}
