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

// Package sshbruteforce implements a vulnerability detector plugin that identifies SSH services
// configured with weak or default credentials.
package sshbruteforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/goonami-scanner/common/clients/sshclient"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// ModuleName is the identifier used to register and reference the SSH brute force detector plugin.
	ModuleName = "dt/sshbruteforce"
)

func init() {
	module.RegisterDetector(ModuleName, New)
}

// Detector is a vulnerability detector module that identifies SSH services with weak credentials.
type Detector struct {
	*module.BaseModule
	cfg    *config.Config
	store  *credentialstore.CredentialStore
	client *sshclient.Client
}

// New creates a new SSH brute-force vulnerability detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	store, err := credentialstore.NewWithDefaults()
	if err != nil {
		return nil, fmt.Errorf("failed to load default credentials for %s: %w", ModuleName, err)
	}

	return &Detector{
		BaseModule: module.NewBaseModule(ModuleName),
		cfg:        cfg,
		store:      store,
		client:     sshclient.New(cfg),
	}, nil
}

type credentialPair struct {
	username string
	password string
}

func (d *Detector) concurrency() int {
	if d.cfg != nil {
		if pluginCfg := d.cfg.PluginsConfig().GetSshbruteforce(); pluginCfg != nil && pluginCfg.GetMaxConcurrency() > 0 {
			return int(pluginCfg.GetMaxConcurrency())
		}
		if perf := d.cfg.GlobalConfig().GetPerformance(); perf != nil && perf.GetMaxConcurrency() > 0 {
			return int(perf.GetMaxConcurrency())
		}
	}
	return 5
}

func (d *Detector) attemptsPerSecond() int {
	if d.cfg != nil {
		if pluginCfg := d.cfg.PluginsConfig().GetSshbruteforce(); pluginCfg != nil && pluginCfg.GetMaxAttemptsPerSecond() > 0 {
			return int(pluginCfg.GetMaxAttemptsPerSecond())
		}
		if perf := d.cfg.GlobalConfig().GetPerformance(); perf != nil && perf.GetMaxPacketsPerSecond() > 0 {
			return int(perf.GetMaxPacketsPerSecond())
		}
	}
	return 0
}

// Detect evaluates whether the target network service is an SSH service vulnerable to weak credentials.
func (d *Detector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	if !IsSSHService(service) {
		return nil, nil
	}

	addr, err := targetAddress(service.GetNetworkEndpoint())
	if err != nil {
		log.WarnContextf(ctx, "failed to get target address for service: %v", err)
		return nil, nil
	}

	usernames := d.store.Usernames()
	if len(usernames) == 0 {
		log.WarnContextf(ctx, "credential store is empty, skipping SSH brute force")
		return nil, nil
	}

	var candidates []credentialPair
	for _, username := range usernames {
		for _, password := range d.store.Passwords(username) {
			candidates = append(candidates, credentialPair{
				username: username,
				password: password,
			})
		}
	}

	if len(candidates) == 0 {
		log.WarnContextf(ctx, "credential store has no passwords, skipping SSH brute force")
		return nil, nil
	}

	var maxAttempts int32
	if pluginCfg := d.cfg.PluginsConfig().GetSshbruteforce(); pluginCfg != nil {
		maxAttempts = pluginCfg.GetMaxAttemptsPerService()
	}

	log.DebugContextf(ctx, log.DebugLevelService, "starting SSH brute force on %s with %d credential(s) (max attempts: %d)", addr, len(candidates), maxAttempts)

	var budgetExhaustedEarly bool
	if maxAttempts > 0 && int32(len(candidates)) > maxAttempts {
		candidates = candidates[:maxAttempts]
		budgetExhaustedEarly = true
	}

	concurrency := d.concurrency()
	if concurrency < 1 {
		concurrency = 1
	}

	qps := d.attemptsPerSecond()
	var limiter *rate.Limiter
	if qps > 0 {
		burst := qps
		if burst < 1 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(qps), burst)
	}

	grpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	group, grpCtx := errgroup.WithContext(grpCtx)
	group.SetLimit(concurrency)

	var (
		mu              sync.Mutex
		foundCred       *credentialPair
		earlyExitReason string
		attempts        atomic.Int32
	)

	for _, cred := range candidates {
		cred := cred
		if grpCtx.Err() != nil {
			break
		}

		group.Go(func() error {
			if grpCtx.Err() != nil {
				return nil
			}

			if limiter != nil {
				if err := limiter.Wait(grpCtx); err != nil {
					return nil
				}
			}

			if grpCtx.Err() != nil {
				return nil
			}

			attemptNum := attempts.Add(1)
			log.DebugContextf(grpCtx, log.DebugLevelRequest, "attempting SSH authentication (%d) with %s:%s on %s", attemptNum, cred.username, cred.password, addr)

			sshConn, err := d.client.Connect(grpCtx, addr, cred.username, cred.password)
			if err == nil {
				if closeErr := sshConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					log.WarnContextf(grpCtx, "failed to close SSH connection to %s: %v", addr, closeErr)
				}
				mu.Lock()
				if foundCred == nil {
					foundCred = &cred
				}
				mu.Unlock()
				cancel()
				return nil
			}

			log.DebugContextf(grpCtx, log.DebugLevelRequest, "SSH authentication attempt (%d) with %s:%s on %s failed: %v", attemptNum, cred.username, cred.password, addr, err)

			switch {
			case errors.Is(err, sshclient.ErrAuthFailed):
				// Credential was rejected; continue brute force.
				return nil
			case errors.Is(err, sshclient.ErrPasswordAuthUnsupported):
				mu.Lock()
				if earlyExitReason == "" {
					earlyExitReason = "password_auth_unsupported"
				}
				mu.Unlock()
				cancel()
				return nil
			case errors.Is(err, sshclient.ErrNotSSHService):
				mu.Lock()
				if earlyExitReason == "" {
					earlyExitReason = "not_ssh_service"
				}
				mu.Unlock()
				cancel()
				return nil
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				return nil
			default:
				log.DebugContextf(grpCtx, log.DebugLevelService, "fatal error probing %s: %v", addr, err)
				return nil
			}
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if foundCred != nil {
		log.DebugContextf(ctx, log.DebugLevelService, "valid SSH credentials found after %d attempt(s): %s:%s on %s", attempts.Load(), foundCred.username, foundCred.password, addr)
		return buildDetectionReport(service, foundCred.username, foundCred.password), nil
	}

	if earlyExitReason == "password_auth_unsupported" {
		log.DebugContextf(ctx, log.DebugLevelService, "SSH server at %s does not support password authentication, terminating early", addr)
		return nil, nil
	}

	if earlyExitReason == "not_ssh_service" {
		log.DebugContextf(ctx, log.DebugLevelService, "target at %s is not an SSH service", addr)
		return nil, nil
	}

	if budgetExhaustedEarly {
		metrics.BudgetExhausted.Add(ctx, 1,
			metrics.Module(d.Name()),
			metrics.LimitName(metrics.LimitMaxAttemptsPerService))
		log.DebugContextf(ctx, log.DebugLevelService, "reached maximum authentication attempts limit of %d on %s", maxAttempts, addr)
		return nil, nil
	}

	log.DebugContextf(ctx, log.DebugLevelService, "no valid SSH credentials found on %s after %d attempt(s)", addr, attempts.Load())
	return nil, nil
}

// IsSSHService returns true if the service has a valid network endpoint to probe.
// It ignores port scanner service hints and allows explicit SSH probing against any service.
func IsSSHService(service *nspb.NetworkService) bool {
	return service != nil && service.GetNetworkEndpoint() != nil
}

func targetAddress(endpoint *npb.NetworkEndpoint) (string, error) {
	if endpoint == nil {
		return "", errors.New("network endpoint is nil")
	}
	authority, err := netendpoint.ToURIAuthority(endpoint)
	if err != nil {
		return "", err
	}
	if _, _, err := net.SplitHostPort(authority); err != nil {
		return net.JoinHostPort(authority, "22"), nil
	}
	return authority, nil
}

func buildDetectionReport(service *nspb.NetworkService, username, password string) *dpb.DetectionReportList {
	additionalDetails := vpb.AdditionalDetail_builder{
		TextData: vpb.TextData_builder{
			Text: fmt.Sprintf("%s:%s", username, password),
		}.Build(),
	}.Build()

	report := dpb.DetectionReport_builder{
		TargetInfo: rpb.TargetInfo_builder{
			NetworkEndpoints: []*npb.NetworkEndpoint{
				service.GetNetworkEndpoint(),
			},
		}.Build(),
		NetworkService:     service,
		DetectionTimestamp: tpb.Now(),
		DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
		Vulnerability: vpb.Vulnerability_builder{
			MainId: vpb.VulnerabilityId_builder{
				Publisher: "GOOGLE",
				Value:     "SSH_WEAK_CREDENTIALS",
			}.Build(),
			Severity:       vpb.Severity_HIGH,
			Title:          "SSH service with weak credentials",
			Description:    "An SSH service with weak credentials has been detected. An attacker could exploit this vulnerability to gain unauthorized remote access to the system.",
			Recommendation: "Change the password to a strong and complex value or disable password-based authentication in favor of public key authentication.",
			AdditionalDetails: []*vpb.AdditionalDetail{
				additionalDetails,
			},
		}.Build(),
	}.Build()

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{report},
	}.Build()
}
