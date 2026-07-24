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

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
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
func (r *SimpleRunner) RegisterPortScanner(ctx context.Context, module module.PortScanner) error {
	ctx = log.ContextForModule(ctx, "core/runner")
	if r.portScanner != nil {
		return ErrPortScannerAlreadyRegistered
	}

	if module == nil {
		return ErrRegistrationNil
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "registering port scanner: %s", module.Name())
	r.portScanner = module
	return nil
}

// RegisterFingerprinter registers an additional fingerprinter.
func (r *SimpleRunner) RegisterFingerprinter(ctx context.Context, module module.Fingerprinter) error {
	ctx = log.ContextForModule(ctx, "core/runner")
	if module == nil {
		return ErrRegistrationNil
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "registering new fingerprinter: %s", module.Name())
	r.fingerprinters = append(r.fingerprinters, module)
	return nil
}

// RegisterDetector registers an additional vulnerability detector.
func (r *SimpleRunner) RegisterDetector(ctx context.Context, module module.VulnDetector) error {
	ctx = log.ContextForModule(ctx, "core/runner")
	if module == nil {
		return ErrRegistrationNil
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "registering new detector: %s", module.Name())
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
	ctx = log.ContextForModule(ctx, "core/runner")
	if len(r.fingerprinters) == 0 {
		log.WarnContextf(ctx, "skipping fingerprinting: no fingerprinters found")
		return rpb.FingerprintingReport_builder{
			NetworkServices: portscan.GetNetworkServices(),
		}.Build(), nil
	}

	return r.runFingerprinters(ctx, portscan)
}

func (r *SimpleRunner) DetectStep(ctx context.Context, fpreport *rpb.FingerprintingReport) ([]*dpb.DetectionReport, error) {
	ctx = log.ContextForModule(ctx, "core/runner")
	if len(r.detectors) == 0 {
		log.WarnContextf(ctx, "skipping detection: no detectors found")
		return nil, nil
	}

	return r.runDetectors(ctx, fpreport)
}

// Run runs the Goonami modules in the order of port scan, fingerprinting and then detection.
func (r *SimpleRunner) Run(ctx context.Context, target string) (*srpb.ScanResults, error) {
	ctx = log.ContextForModule(ctx, "core/runner")
	portscan, err := r.PortScanStep(ctx, target)
	if err != nil {
		return nil, err
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "port scan complete: Found %d open services", len(portscan.GetNetworkServices()))
	fpreport, err := r.FingerprintStep(ctx, portscan)
	if err != nil {
		return nil, err
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "fingerprinting phase complete")
	detections, err := r.DetectStep(ctx, fpreport)
	if err != nil {
		return nil, err
	}

	results := srpb.ScanResults_builder{
		ScanStatus: srpb.ScanStatus_SUCCEEDED,
		ReconnaissanceReport: rpb.ReconnaissanceReport_builder{
			TargetInfo:      portscan.GetTargetInfo(),
			NetworkServices: fpreport.GetNetworkServices(),
		}.Build(),
		FullDetectionReports: srpb.FullDetectionReports_builder{
			DetectionReports: detections,
		}.Build(),
	}.Build()

	log.DebugContextf(ctx, log.DebugLevelSession, "scan complete")
	return results, nil
}

func (r *SimpleRunner) runFingerprinters(ctx context.Context, portscan *rpb.PortScanningReport) (*rpb.FingerprintingReport, error) {
	concurrency := int(r.config.GlobalConfig().GetPerformance().GetMaxConcurrency())
	services, err := runConcurrent(ctx, concurrency, portscan.GetNetworkServices(), r.fingerprintService)
	if err != nil {
		return nil, err
	}

	return rpb.FingerprintingReport_builder{
		NetworkServices: services,
	}.Build(), nil
}

func (r *SimpleRunner) runDetectors(ctx context.Context, fpreport *rpb.FingerprintingReport) ([]*dpb.DetectionReport, error) {
	concurrency := int(r.config.GlobalConfig().GetPerformance().GetMaxConcurrency())
	return runConcurrent(ctx, concurrency, fpreport.GetNetworkServices(), r.detectService)
}

// processFn abstract a function that is run concurrently against a specific network service.
type processFn[E any] func(context.Context, *nspb.NetworkService) ([]E, error)

// runConcurrent goes through the network services and apply processSvc to all of them concurrently.
// Then, it accumulates the results and returns them all together.
func runConcurrent[E any](ctx context.Context, concurrency int, services []*nspb.NetworkService, processSvc processFn[E]) ([]E, error) {
	var results []E
	var mut sync.Mutex
	group, grpctx := errgroup.WithContext(ctx)
	group.SetLimit(concurrency)

	for _, service := range services {
		if grpctx.Err() != nil {
			return nil, grpctx.Err()
		}

		group.Go(func() error {
			serviceCpy := proto.Clone(service).(*nspb.NetworkService)
			res, err := processSvc(grpctx, serviceCpy)
			if err != nil {
				return err
			}

			mut.Lock()
			defer mut.Unlock()
			results = append(results, res...)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

// Note fingerprintService fingerprints a specific service. It starts with only one network service
// coming directly from the port scan. But each fingerprinter can technically "split" that network
// service into several ones.
func (r *SimpleRunner) fingerprintService(ctx context.Context, svc *nspb.NetworkService) ([]*nspb.NetworkService, error) {
	var services []*nspb.NetworkService = []*nspb.NetworkService{svc}
	for _, fp := range r.fingerprinters {
		var accumulator []*nspb.NetworkService

		for _, sv := range services {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			ctx = log.ContextForModuleAndService(ctx, fp.Name(), sv)
			res, err := fp.Fingerprint(ctx, sv)
			if err != nil {
				log.ErrorContextf(ctx, "fatal fingerprinting error: %s", err)
				return nil, err
			}

			accumulator = append(accumulator, res...)
		}

		services = accumulator
	}

	return services, nil
}

func (r *SimpleRunner) detectService(ctx context.Context, svc *nspb.NetworkService) ([]*dpb.DetectionReport, error) {
	var reports []*dpb.DetectionReport

	for _, dt := range r.detectors {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		ctx = log.ContextForModuleAndService(ctx, dt.Name(), svc)
		res, err := dt.Detect(ctx, svc)
		if err != nil {
			log.ErrorContextf(ctx, "fatal detection error: %s", err)
			return nil, err
		}

		if len(res.GetDetectionReports()) > 0 {
			log.VulnContextf(ctx, "module %s has reported at least one vulnerability", dt.Name())
		}

		reports = append(reports, res.GetDetectionReports()...)
	}

	return reports, nil
}
