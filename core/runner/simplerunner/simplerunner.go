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

// Package simplerunner provides a base runner for Goonami.
package simplerunner

import (
	"context"
	"errors"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

var (
	// ErrRegistrationNil when trying to register a nil module.
	ErrRegistrationNil = errors.New("cannot perform registration: provided module is nil")

	// ErrPortScannerAlreadyRegistered when trying to register more than one port scanner.
	ErrPortScannerAlreadyRegistered = errors.New("port scanner already registered")

	// ErrNoPortScanner when trying to run the scan without any port scanner registered.
	ErrNoPortScanner = errors.New("no port scanner found")

	// ErrConfigNil when trying to create a runner with nil config.
	ErrConfigNil = errors.New("cannot create a runner with nil config")
)

// SimpleRunner is the default runner used by Goonami. It provides a simple orchestration for
// modules. It allows registering exactly one port scanner and then several fingerprinters and
// vulnerability detectors.
type SimpleRunner struct {
	config         *config.Config
	portScanner    module.PortScanner
	fingerprinters []module.Fingerprinter
	detectors      []module.VulnDetector
}

// New creates a new SimpleRunner.
func New(config *config.Config) (*SimpleRunner, error) {
	if config == nil {
		return nil, ErrConfigNil
	}

	return &SimpleRunner{
		config:         config,
		portScanner:    nil,
		fingerprinters: []module.Fingerprinter{},
		detectors:      []module.VulnDetector{},
	}, nil
}

// RegisterPortScanner registers the port scanner (only one port scanner can be registered).
func (r *SimpleRunner) RegisterPortScanner(module module.PortScanner) error {
	if r.portScanner != nil {
		return ErrPortScannerAlreadyRegistered
	}

	if module == nil {
		return ErrRegistrationNil
	}

	log.Debugf(log.DebugLevelSession, "[runner] registering port scanner: %s", module.Name())
	r.portScanner = module
	return nil
}

// RegisterFingerprinter registers an additional fingerprinter.
func (r *SimpleRunner) RegisterFingerprinter(module module.Fingerprinter) error {
	if module == nil {
		return ErrRegistrationNil
	}

	log.Debugf(log.DebugLevelSession, "[runner] registering new fingerprinter: %s", module.Name())
	r.fingerprinters = append(r.fingerprinters, module)
	return nil
}

// RegisterDetector registers an additional vulnerability detector.
func (r *SimpleRunner) RegisterDetector(module module.VulnDetector) error {
	if module == nil {
		return ErrRegistrationNil
	}

	log.Debugf(log.DebugLevelSession, "[runner] registering new detector: %s", module.Name())
	r.detectors = append(r.detectors, module)
	return nil
}

// PortScanStep runs the port scanner against the given target and returns the port scanning report.
func (r *SimpleRunner) PortScanStep(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	if r.portScanner == nil {
		return nil, ErrNoPortScanner
	}

	return r.portScanner.Scan(ctx, target)
}

// FingerprintStep runs fingerprinting (in place) from the port scanning report.
func (r *SimpleRunner) FingerprintStep(ctx context.Context, portscan *rpb.PortScanningReport) (*rpb.FingerprintingReport, error) {
	if len(r.fingerprinters) == 0 {
		log.Warnf("[runner] skipping fingerprinting: no fingerprinters found")
		return rpb.FingerprintingReport_builder{
			NetworkServices: portscan.GetNetworkServices(),
		}.Build(), nil
	}

	return r.runFingerprinters(ctx, portscan)
}

// Run runs the Goonami modules in the order of port scan, fingerprinting and then detection.
func (r *SimpleRunner) Run(ctx context.Context, target string) (*srpb.ScanResults, error) {
	portscan, err := r.PortScanStep(ctx, target)
	if err != nil {
		return nil, err
	}

	log.Debugf(log.DebugLevelSession, "[runner] Port scan complete. Found %d open services", len(portscan.GetNetworkServices()))
	fingerprints, err := r.FingerprintStep(ctx, portscan)
	if err != nil {
		return nil, err
	}

	results := srpb.ScanResults_builder{
		ReconnaissanceReport: rpb.ReconnaissanceReport_builder{
			TargetInfo:      portscan.GetTargetInfo(),
			NetworkServices: fingerprints.GetNetworkServices(),
		}.Build(),
	}.Build()

	// TODO: b/456152069 - Perform vulnerability detection here.

	log.Debugf(log.DebugLevelSession, "[runner] Fingerprinting phase complete.")
	return results, nil
}

func (r *SimpleRunner) runFingerprinters(ctx context.Context, portscan *rpb.PortScanningReport) (*rpb.FingerprintingReport, error) {
	report := &rpb.FingerprintingReport_builder{}
	var mut sync.Mutex
	group, grpctx := errgroup.WithContext(ctx)
	group.SetLimit(int(r.config.GlobalConfig().GetPerformance().GetMaxConcurrency()))

	for _, netservice := range portscan.GetNetworkServices() {
		if grpctx.Err() != nil {
			return nil, grpctx.Err()
		}

		group.Go(func() error {
			ns, err := r.fingerprintService(grpctx, portscan.GetTargetInfo(), netservice)
			if err != nil {
				return err
			}

			mut.Lock()
			defer mut.Unlock()
			report.NetworkServices = append(report.NetworkServices, ns)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return report.Build(), nil
}

// note: Fingerprinters work in place. That means that they will modify we provide as input. To
// avoid side-effects, we provide them with a deep-copy.
func (r *SimpleRunner) fingerprintService(ctx context.Context, target *rpb.TargetInfo, svc *nspb.NetworkService) (*nspb.NetworkService, error) {
	svcCopy := proto.Clone(svc).(*nspb.NetworkService)
	for _, fp := range r.fingerprinters {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if err := fp.Fingerprint(ctx, svcCopy); err != nil {
			return nil, err
		}
	}

	return svcCopy, nil
}
