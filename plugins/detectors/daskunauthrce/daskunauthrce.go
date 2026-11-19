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

// Package daskunauthrce detects exposed unauthenticated Dask Distributed and
// NVIDIA RAPIDS cluster endpoints allowing arbitrary remote code execution.
package daskunauthrce

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

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
	moduleName = "dt/daskunauthrce"

	minProbeOperand int32 = 10_000_000
	operandSpan     int32 = 40_000_000

	vulnPublisher      = "GOOGLE"
	vulnID             = "DASK_DISTRIBUTED_UNAUTHENTICATED_RCE"
	vulnTitle          = "Exposed Unauthenticated Dask Distributed Cluster RCE"
	vulnDescription    = "The target exposes an unauthenticated Dask Distributed (or NVIDIA RAPIDS dask-cuda) cluster RPC endpoint that permits arbitrary Python code execution via the 'run_function', 'broadcast', or 'run' Comm RPC handlers without TLS client-certificate authentication."
	vulnRecommendation = "Restrict network access to Dask Scheduler and Worker ports using firewall rules or private cluster networking, enforce mutual TLS authentication ('distributed.comm.require-encryption: true' with 'distributed.comm.tls.ca-file' and node certificates), and block arbitrary code-execution RPC handlers ('distributed.scheduler.blocked-handlers: [broadcast, feed, run, run_function]', 'distributed.worker.blocked-handlers: [run]', and 'distributed.nanny.blocked-handlers: [run]')."
)

// Module implements module.VulnDetector for exposed unauthenticated Dask
// Distributed and NVIDIA RAPIDS cluster endpoints.
type Module struct {
	*module.BaseModule
	config       *config.Config
	operandGenFn func() (int32, int32, error)
}

func init() {
	module.RegisterDetector(moduleName, New)
}

// New constructs a new Dask Distributed unauthenticated RCE detector module.
func New(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
	return &Module{
		BaseModule:   module.NewBaseModule(moduleName),
		config:       cfg,
		operandGenFn: randomOperandPair,
	}, nil
}

// Advisories returns the vulnerability advisory reported by this module.
func (m *Module) Advisories() []*vpb.Vulnerability {
	return []*vpb.Vulnerability{baseVulnerability()}
}

func baseVulnerability() *vpb.Vulnerability {
	return vpb.Vulnerability_builder{
		MainId: vpb.VulnerabilityId_builder{
			Publisher: vulnPublisher,
			Value:     vulnID,
		}.Build(),
		Severity:       vpb.Severity_CRITICAL,
		Title:          vulnTitle,
		Description:    vulnDescription,
		Recommendation: vulnRecommendation,
	}.Build()
}

// Detect probes the target service for unauthenticated Dask Distributed RCE
// across raw TCP/TLS Comm endpoints and WebSocket Comm endpoints.
func (m *Module) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	ctx = log.ContextForModuleAndService(ctx, m.Name(), service) // NOMUTANTS -- diagnostic logging context
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if proto := service.GetTransportProtocol(); proto != npb.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED && proto != npb.TransportProtocol_TCP {
		return nil, nil
	}

	authority, err := netendpoint.ToURIAuthority(service.GetNetworkEndpoint())
	if err != nil {
		return nil, err
	}

	res, err := m.probeCommService(ctx, service, authority)
	if err != nil || res == nil {
		return nil, err
	}

	return buildDetectionReport(service, res), nil
}

func (m *Module) probeCommService(ctx context.Context, service *nspb.NetworkService, authority string) (*commResult, error) {
	a, b, err := m.operandGenFn()
	if err != nil {
		return nil, err
	}

	useTLS := netservice.HasTLS(service)
	timeout := m.config.TimeoutPerRequest()

	var res *commResult
	if netservice.IsWebService(service) {
		res, err = probeCommWebSocket(ctx, authority, useTLS, timeout, a, b)
	} else {
		res, err = probeCommTCP(ctx, authority, useTLS, timeout, a, b)
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		log.DebugContextf(ctx, log.DebugLevelService, "Dask Comm probe to %q did not match: %v", authority, err) // NOMUTANTS -- diagnostic logging
		return nil, nil
	}
	return res, nil
}

func randomOperandPair() (int32, int32, error) {
	return randomOperandPairFrom(rand.Reader)
}

func randomOperandPairFrom(r io.Reader) (int32, int32, error) {
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, 0, err
	}
	a := minProbeOperand + int32(binary.LittleEndian.Uint32(raw[0:4])%uint32(operandSpan))
	b := minProbeOperand + int32(binary.LittleEndian.Uint32(raw[4:8])%uint32(operandSpan))
	return a, b, nil
}

func buildDetectionReport(service *nspb.NetworkService, res *commResult) *dpb.DetectionReportList {
	evidence := fmt.Sprintf(
		"Verified unauthenticated Dask %s (%s) code execution on %s via %s RPC handler: operator.add(%d, %d) returned %d.",
		res.daemonType, res.daemonID, res.commAddr, res.handler, res.operandA, res.operandB, res.computedSum,
	)

	vuln := baseVulnerability()
	vuln.SetAdditionalDetails([]*vpb.AdditionalDetail{
		vpb.AdditionalDetail_builder{
			Description: "Verified unauthenticated Dask Distributed RPC code execution",
			TextData: vpb.TextData_builder{
				Text: evidence,
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
