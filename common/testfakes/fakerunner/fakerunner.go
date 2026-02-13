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

// Package fakerunner provides a fake implementation of the Goonami runner.
package fakerunner

import (
	"context"

	"github.com/google/goonami-scanner/core/module"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

// OverrideRunFn is the type of function that overrides the Run() of the fake runner.
type OverrideRunFn func(ctx context.Context, target string) (*srpb.ScanResults, error)

// OverrideRegisterPortScannerFn is the type of function that overrides the RegisterPortScanner()
// of the fake runner.
type OverrideRegisterPortScannerFn func(ctx context.Context, ps module.PortScanner) error

// OverrideRegisterFingerprinterFn is the type of function that overrides the
// RegisterFingerprinter() of the fake runner.
type OverrideRegisterFingerprinterFn func(ctx context.Context, fp module.Fingerprinter) error

// OverrideRegisterDetectorFn is the type of function that overrides the RegisterDetector() of the
// fake runner.
type OverrideRegisterDetectorFn func(ctx context.Context, d module.VulnDetector) error

// FakeRunner is a fake implementation of the Goonami runner. It provides more introspection
// capabilities than the real runner.
type FakeRunner struct {
	portScanner    module.PortScanner
	fingerprinters []module.Fingerprinter
	detectors      []module.VulnDetector

	overrideRun                   OverrideRunFn
	overrideRegisterPort          OverrideRegisterPortScannerFn
	overrideRegisterFingerprinter OverrideRegisterFingerprinterFn
	overrideRegisterDetector      OverrideRegisterDetectorFn
}

// New creates a new fake runner.
func New() *FakeRunner {
	return &FakeRunner{}
}

// OverrideRegisterPortScanner function.
func (r *FakeRunner) OverrideRegisterPortScanner(fn OverrideRegisterPortScannerFn) {
	r.overrideRegisterPort = fn
}

// RegisterPortScanner registers a port scanner with the fake runner.
func (r *FakeRunner) RegisterPortScanner(ctx context.Context, ps module.PortScanner) error {
	if r.overrideRegisterPort != nil {
		return r.overrideRegisterPort(ctx, ps)
	}

	r.portScanner = ps
	return nil
}

// PortScanner returns the port scanner registered with the fake runner.
func (r *FakeRunner) PortScanner() module.PortScanner {
	return r.portScanner
}

// OverrideRegisterFingerprinter function.
func (r *FakeRunner) OverrideRegisterFingerprinter(fn OverrideRegisterFingerprinterFn) {
	r.overrideRegisterFingerprinter = fn
}

// RegisterFingerprinter registers a fingerprinter with the fake runner.
func (r *FakeRunner) RegisterFingerprinter(ctx context.Context, fp module.Fingerprinter) error {
	if r.overrideRegisterFingerprinter != nil {
		return r.overrideRegisterFingerprinter(ctx, fp)
	}

	r.fingerprinters = append(r.fingerprinters, fp)
	return nil
}

// Fingerprinters returns the fingerprinters registered with the fake runner.
func (r *FakeRunner) Fingerprinters() []module.Fingerprinter {
	return r.fingerprinters
}

// OverrideRegisterDetector function.
func (r *FakeRunner) OverrideRegisterDetector(fn OverrideRegisterDetectorFn) {
	r.overrideRegisterDetector = fn
}

// RegisterDetector registers a detector with the fake runner.
func (r *FakeRunner) RegisterDetector(ctx context.Context, d module.VulnDetector) error {
	if r.overrideRegisterDetector != nil {
		return r.overrideRegisterDetector(ctx, d)
	}

	r.detectors = append(r.detectors, d)
	return nil
}

// Detectors returns the detectors registered with the fake runner.
func (r *FakeRunner) Detectors() []module.VulnDetector {
	return r.detectors
}

// OverrideRun function.
func (r *FakeRunner) OverrideRun(fn OverrideRunFn) {
	r.overrideRun = fn
}

// Run runs the fake runner.
func (r *FakeRunner) Run(ctx context.Context, target string) (*srpb.ScanResults, error) {
	if r.overrideRun != nil {
		return r.overrideRun(ctx, target)
	}

	return nil, nil
}
