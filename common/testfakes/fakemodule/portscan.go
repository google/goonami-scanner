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

// Package fakemodule provides fake implementations of Goonami modules for testing.
package fakemodule

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"

	rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

// FakePortScanFn is the function that overrides the Scan() of the fake port scanner.
type FakePortScanFn func(ctx context.Context, target string) (*rpb.PortScanningReport, error)

// FakePortScanFnDoNothing is a Scan() that does nothing.
func FakePortScanFnDoNothing(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	return nil, nil
}

// ErrFakePortScanGeneric is a generic fake port scan error.
var ErrFakePortScanGeneric = errors.New("generic fake port scanning error")

// FakePortScanFnErrors is a Scan() that returns a generic error.
func FakePortScanFnErrors(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	return nil, ErrFakePortScanGeneric
}

// FakePortScanner is a test double for module.PortScanner. It is not concurrency safe.
type FakePortScanner struct {
	*module.BaseModule
	scanCalls int
	override  FakePortScanFn
}

// NewFakePortScanner creates a new FakePortScanner.
func NewFakePortScanner(name string, override FakePortScanFn) *FakePortScanner {
	return &FakePortScanner{
		BaseModule: module.NewBaseModule(name),
		override:   override,
	}
}

// CountCalls returns the number of times the Scan method was called.
func (m *FakePortScanner) CountCalls() int {
	return m.scanCalls
}

// Scan the target using the registered override function.
func (m *FakePortScanner) Scan(ctx context.Context, target string) (*rpb.PortScanningReport, error) {
	m.scanCalls++
	return m.override(ctx, target)
}

// InitFakePortScanner return an init function for the FakePortScanner. If err is provided, the
// init function will immediately return it.
func InitFakePortScanner(name string, err error, override FakePortScanFn) module.InitPortScannerFn {
	return func(c *config.Config) (module.PortScanner, error) {
		if err != nil {
			return nil, err
		}

		return NewFakePortScanner(name, override), nil
	}
}
