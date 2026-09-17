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

// Package adkweakcreds leverages LLMs to brute-force credentials.
package adkweakcreds

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/goonami-scanner/common/clients/llm"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"github.com/google/goonami-scanner/core/net/netservice"
	"github.com/google/goonami-scanner/plugins/detectors/adkweakcreds/cache"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/genai"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	moduleName = "dt/adkweakcreds"
)

// finding contains the valid credentials discovered and the requests used.
type finding struct {
	ValidCredentials []*validCredential `json:"valid_credentials"`
	LoginRequest     *request           `json:"login_request"`
	CsrfRequest      *request           `json:"csrf_request"`
}

// Module is the main structure of the module.
type Module struct {
	*module.BaseModule
	coreConfig   *config.Config
	agentBuilder func(context.Context, *config.Config, *nspb.NetworkService) (agent.Agent, error)
	index        *cache.Index
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New returns a new instance of the module.
func New(ctx context.Context, config *config.Config) (module.VulnDetector, error) {
	cachePath, err := config.GetCacheForModule(moduleName)
	if err != nil {
		log.WarnContextf(ctx, "failed to get cache directory, caching will be disabled: %v", err)
		cachePath = ""
	}

	return &Module{
		BaseModule:   module.NewBaseModule(moduleName),
		coreConfig:   config,
		agentBuilder: buildAgent,
		index:        cache.Load(ctx, cachePath),
	}, nil
}

// Detect performs the vulnerability detection process by interacting with the LLM agent and executing the brute-force strategy.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	if !netservice.IsWebService(service) {
		return nil, nil
	}

	strategy, err := m.getStrategy(ctx, service)
	if err != nil {
		return nil, err
	}

	if strategy == nil {
		return nil, nil
	}

	finding, err := strategy.bruteforce(ctx, m.coreConfig, service)
	if err != nil {
		return nil, err
	}

	if finding == nil {
		return nil, nil
	}

	return m.buildDetectionReport(ctx, service, *finding)
}

func (m *Module) getStrategy(ctx context.Context, service *nspb.NetworkService) (*authStrategy, error) {
	if m.index != nil {
		data, found := m.index.FindForService(ctx, m.coreConfig, service)
		if found && data != nil {
			log.DebugContextf(ctx, log.DebugLevelService, "found cached strategy")
			return strategyFromJSON(string(data))
		}
	}

	ag, err := m.agentBuilder(ctx, m.coreConfig, service)
	if err != nil {
		return nil, err
	}

	client := llm.New(m.coreConfig, ag)
	verifier := func(ctx context.Context, result string) error {
		return m.assertStrategyQuality(ctx, service, result)
	}

	prompt := "Identify whether the web service supports authentication and determine the credential testing strategy"
	if webRoot, err := netservice.BuildWebRoot(service); err == nil {
		prompt = fmt.Sprintf("Identify whether the web service at %s supports authentication and determine the credential testing strategy", webRoot)
	}

	log.DebugContextf(ctx, log.DebugLevelService, "running agent: %s", prompt)
	content := &genai.Content{
		Role:  "user",
		Parts: []*genai.Part{{Text: prompt}},
	}
	result, err := client.RunWithFeedbackLoop(ctx, content, verifier)
	if err != nil {
		// Note: we do not propagate model related errors as we do not want them to stop Goonami
		// altogether.
		return nil, nil
	}

	strategy, err := strategyFromJSON(result)
	if err != nil {
		return nil, err
	}

	if m.index != nil && strategy.SupportsAuthentication {
		log.DebugContextf(ctx, log.DebugLevelService, "adding strategy to cache")
		if err := m.index.Add(ctx, m.coreConfig, service, strategy.AuthDetails.LoginRequest.Path, []byte(result)); err != nil {
			log.WarnContextf(ctx, "failed to write strategy back to cache: %v", err)
		}
	}

	return strategy, nil
}

// assertStrategyQuality verifies the strategy produced by the LLM by testing it against invalid credentials
// to confirm that the failure extraction regex matches the rejection response.
func (m *Module) assertStrategyQuality(ctx context.Context, service *nspb.NetworkService, result string) error {
	log.DebugContextf(ctx, log.DebugLevelRequest, "agent's unverified strategy: %v", result)
	strategy, err := strategyFromJSON(result)
	if err != nil {
		return err
	}

	if !strategy.SupportsAuthentication {
		log.DebugContextf(ctx, log.DebugLevelService, "agent reported that the service does not support authentication")
		return nil
	}

	// Perform an invalid login attempt to confirm that the strategy correctly detects authentication failures.
	invalidCred := strategy.getInvalidCredential()
	resp, err := strategy.login(ctx, m.coreConfig, service, invalidCred)
	if err != nil {
		return err
	}

	// Confirm that the extraction regex successfully matched the negative validation response.
	if resp.Extraction == nil {
		return errRegexpTooWeak
	}

	log.DebugContextf(ctx, log.DebugLevelService, "agent's strategy verified, ready to brute force")
	return nil
}

// buildDetectionReport constructs the final vulnerability detection report with the valid credentials.
func (m *Module) buildDetectionReport(ctx context.Context, service *nspb.NetworkService, finding finding) (*dpb.DetectionReportList, error) {
	extraDetails, err := json.Marshal(finding)
	if err != nil {
		return nil, err
	}

	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				TargetInfo: rpb.TargetInfo_builder{
					NetworkEndpoints: []*npb.NetworkEndpoint{
						service.GetNetworkEndpoint(),
					},
				}.Build(),
				NetworkService:     service,
				DetectionTimestamp: tpb.Now(),
				DetectionStatus:    determineStatus(finding),
				Vulnerability: vpb.Vulnerability_builder{
					Title:          "Web-service with weak credentials",
					Severity:       vpb.Severity_HIGH,
					Description:    "A web service with weak credentials has been detected. An attacker could guess these credentials and gain access to the service.",
					Recommendation: "Use firewalling to restrict access to the service and use strong credentials and consider using multi-factor authentication.",
					MainId: vpb.VulnerabilityId_builder{
						Publisher: "GOOGLE",
						Value:     "GENERIC_AGENTIC_WEAK_CREDENTIALS",
					}.Build(),
					AdditionalDetails: []*vpb.AdditionalDetail{
						vpb.AdditionalDetail_builder{
							TextData: vpb.TextData_builder{
								Text: string(extraDetails),
							}.Build(),
						}.Build(),
					},
				}.Build(),
			}.Build(),
		},
	}.Build(), nil
}

func determineStatus(finding finding) dpb.DetectionStatus {
	status := dpb.DetectionStatus_VULNERABILITY_PRESENT
	for _, cred := range finding.ValidCredentials {
		if cred.Confidence == confidenceHigh {
			status = dpb.DetectionStatus_VULNERABILITY_VERIFIED
			break
		}
	}
	return status
}
