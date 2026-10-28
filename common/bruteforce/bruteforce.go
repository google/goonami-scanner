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

// Package bruteforce provides a generic brute-force library with rate limiting,
// bounded concurrency, and safety budgets for credential-testing vulnerability
// detectors.
package bruteforce

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/proto"

	bfpb "github.com/google/goonami-scanner/common/bruteforce/bruteforce_config_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrConfigNil is returned when the provided configuration is nil.
	ErrConfigNil = errors.New("config is nil")

	// ErrHandlerNil is returned when the provided brute-force handler is nil.
	ErrHandlerNil = errors.New("handler is nil")

	// ErrVulnerabilityNil is returned when the handler's base vulnerability is nil.
	ErrVulnerabilityNil = errors.New("handler vulnerability is nil")
)

// Detector is a generic brute-force vulnerability detector that wraps a Handler
// with rate limiting, bounded concurrency, and attempt budgets.
type Detector struct {
	*module.BaseModule
	config  *bfpb.BruteForceConfig
	handler Handler
	store   *credentialstore.CredentialStore
}

// New creates a new generic brute-force Detector wrapping the given Handler.
func New(ctx context.Context, cfg *config.Config, handler Handler, opts *Options) (*Detector, error) {
	if cfg == nil {
		return nil, ErrConfigNil
	}
	if handler == nil {
		return nil, ErrHandlerNil
	}
	if handler.Vulnerability() == nil {
		return nil, ErrVulnerabilityNil
	}
	if opts == nil {
		opts = &Options{}
	}

	ctx = log.ContextForModule(ctx, handler.Name())

	bfCfg := cfg.PluginsConfig().GetBruteforce()
	if bfCfg.GetMaxConcurrency() <= 0 {
		bfCfg.SetMaxConcurrency(1)
	}

	store, err := opts.prepareCredentialStore(ctx)
	if err != nil {
		return nil, err
	}

	return &Detector{
		BaseModule: module.NewBaseModule(handler.Name()),
		config:     bfCfg,
		handler:    handler,
		store:      store,
	}, nil
}

// CredentialStore returns a copy of the detector's configured credential store.
func (d *Detector) CredentialStore() *credentialstore.CredentialStore {
	return d.store.Copy()
}

// Detect fingerprints the target service and brute-forces credentials up to the
// configured budget, reporting discovered weak credentials.
func (d *Detector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, d.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	matched, err := d.handler.Fingerprint(ctx, service)
	if err != nil {
		return nil, err
	}
	if !matched {
		log.DebugContextf(ctx, log.DebugLevelService, "service fingerprinting did not match for %q, skipping brute-forcing", d.Name())
		return nil, nil
	}

	creds, budgetExhausted := d.budgetedCandidates(ctx)
	validCreds, err := testCredentials(ctx, d.config, d.handler.NewWorker, service, creds)
	if err != nil {
		return nil, err
	}

	if budgetExhausted {
		d.recordBudgetExhausted(ctx)
	}

	if len(validCreds) == 0 {
		log.DebugContextf(ctx, log.DebugLevelService, "no valid credentials found after %d attempt(s)", len(creds))
		return nil, nil
	}

	return d.buildDetectionReportList(service, validCreds), nil
}

func (d *Detector) budgetedCandidates(ctx context.Context) ([]Credential, bool) {
	maxAttempts := d.config.GetMaxAttemptsPerService()
	creds := d.candidates()
	log.DebugContextf(ctx, log.DebugLevelService, "%d credentials generated (max attempts: %d) and will be used against the service", len(creds), maxAttempts)

	if maxAttempts > 0 && len(creds) > int(maxAttempts) {
		return creds[:maxAttempts], true
	}
	return creds, false
}

func (d *Detector) recordBudgetExhausted(ctx context.Context) {
	maxAttempts := d.config.GetMaxAttemptsPerService()
	metrics.BudgetExhausted.Add(ctx, 1,
		metrics.Module(d.Name()),
		metrics.LimitName(metrics.LimitMaxAttemptsPerService))
	log.DebugContextf(ctx, log.DebugLevelService, "reached maximum authentication attempts limit of %d", maxAttempts)
}

func (d *Detector) candidates() []Credential {
	var creds []Credential
	for _, username := range d.store.Usernames() {
		for _, password := range d.store.Passwords(username) {
			creds = append(creds, Credential{
				Username: username,
				Password: password,
			})
		}
	}
	return creds
}

func (d *Detector) buildDetectionReportList(service *nspb.NetworkService, validCreds []Credential) *dpb.DetectionReportList {
	vuln := proto.CloneOf(d.handler.Vulnerability())

	details := vuln.GetAdditionalDetails()
	for _, cred := range validCreds {
		details = append(details, vpb.AdditionalDetail_builder{
			Description: "Weak credential found in format username:password",
			TextData: vpb.TextData_builder{
				Text: cred.String(),
			}.Build(),
		}.Build())
	}
	vuln.SetAdditionalDetails(details)

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{service.GetNetworkEndpoint()},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tspb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
