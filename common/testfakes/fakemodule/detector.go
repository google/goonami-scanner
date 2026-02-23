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

package fakemodule

import (
	"context"
	"errors"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"

	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// FakeDetectFn is the function that overrides the Detect() of the fake detector.
type FakeDetectFn func(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error)

// FakeDetectFnNoFindings is a fake Detect function that does nothing.
func FakeDetectFnNoFindings(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	return nil, nil
}

// ErrFakeDetectGeneric is a generic fake detection error.
var ErrFakeDetectGeneric = errors.New("generic fake detection error")

// FakeDetectFnErrors is a fake fingerprinting function that errors out.
func FakeDetectFnErrors(ctx context.Context, svc *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	return nil, ErrFakeDetectGeneric
}

// FakeVulnDetector is a test double for module.VulnDetector.
type FakeVulnDetector struct {
	*module.BaseModule
	override  FakeDetectFn
	mut       sync.Mutex
	scanCalls int
}

// Detect returns a detection report for the given network service.
func (m *FakeVulnDetector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	m.mut.Lock()
	m.scanCalls++
	m.mut.Unlock()

	return m.override(ctx, service)
}

// CountCalls returns the number of times the Detect method was called.
func (m *FakeVulnDetector) CountCalls() int {
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.scanCalls
}

// NewFakeVulnDetector creates a new FakeVulnDetector.
func NewFakeVulnDetector(name string, override FakeDetectFn) *FakeVulnDetector {
	return &FakeVulnDetector{
		BaseModule: module.NewBaseModule(name),
		override:   override,
	}
}

// InitFakeVulnDetector return an init function for the FakeVulnDetector. If err is provided, the
// init function will immediately return it.
func InitFakeVulnDetector(name string, err error, override FakeDetectFn) module.InitVulnDetectorFn {
	return func(ctx context.Context, c *config.Config) (module.VulnDetector, error) {
		if err != nil {
			return nil, err
		}

		return NewFakeVulnDetector(name, override), nil
	}
}
