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

// Package postgres implements a weak credentials detector for PostgreSQL services.
package postgres

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/clients/postgresclient"
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
	// ModuleName is the name of the PostgreSQL weak credentials detector module.
	ModuleName = "dt/wk/postgres"

	probeUser     = "goonami_fp_probe"
	probePassword = "goonami_fp_probe_invalid_pass_9f8a7b"
)

func init() {
	module.RegisterDetector(ModuleName, New)
}

// DefaultCredentials returns the default PostgreSQL credentials to test, matching Tsunami's
// service_default_credentials.textproto for POSTGRES and augmented with the common default password.
func DefaultCredentials() []bruteforce.Credential {
	return []bruteforce.Credential{
		{Username: "postgres", Password: ""},
		{Username: "postgres", Password: "postgres"},
	}
}

// BaseVulnerability returns the base vulnerability metadata for weak PostgreSQL credentials.
func BaseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "POSTGRES_WEAK_CREDENTIALS",
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          "PostgreSQL Weak Credentials",
		Description:    "The PostgreSQL database service is configured with weak or default credentials, allowing unauthorized access to the database.",
		Recommendation: "Set a strong, unique password for all PostgreSQL database accounts and restrict network access using pg_hba.conf and firewall rules.",
	}.Build()
}

// Handler implements bruteforce.Handler and bruteforce.Worker for PostgreSQL services.
type Handler struct {
	client *postgresclient.Client
}

// NewHandler creates a new PostgreSQL brute-force handler using the given configuration.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		client: postgresclient.New(cfg),
	}
}

// New creates a new PostgreSQL weak credentials detector with default options.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	store, err := credentialstore.NewWithDefaults()
	if err != nil {
		return nil, err
	}
	_ = store.AddUser("postgres")
	store.AddMultiplePasswordsForUser("postgres", store.Passwords("root"))
	return NewWithOptions(ctx, cfg, &bruteforce.Options{
		CredentialStore:    store,
		DefaultCredentials: DefaultCredentials(),
	})
}

// NewWithOptions creates a new PostgreSQL weak credentials detector with custom brute-force options.
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

// Fingerprint determines whether the service is a PostgreSQL server that accepts password authentication.
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

	db, err := h.client.Connect(ctx, addr, probeUser, probePassword, postgresclient.DefaultDatabase)
	if err == nil {
		_ = db.Close()
		return true, nil
	}
	if errors.Is(err, postgresclient.ErrAuthFailed) {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	log.DebugContextf(ctx, log.DebugLevelService, "Service at %s is not a password-authenticating PostgreSQL server: %v", addr, err)
	return false, nil
}

// NewWorker returns a bruteforce.Worker for testing PostgreSQL credentials on a single goroutine.
func (h *Handler) NewWorker() bruteforce.Worker {
	return h
}

// TestCredential tests a single username/password pair against the PostgreSQL service.
func (h *Handler) TestCredential(ctx context.Context, service *nspb.NetworkService, cred bruteforce.Credential) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return false, err
	}

	db, err := h.client.Connect(ctx, addr, cred.Username, cred.Password, postgresclient.DefaultDatabase)
	if err == nil {
		_ = db.Close()
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if errors.Is(err, postgresclient.ErrAuthFailed) {
		return false, nil
	}
	return false, err
}

// Close releases any resources held by the worker.
func (h *Handler) Close() error {
	return nil
}
