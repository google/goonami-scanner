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
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
)

// FakeVulnDetector is a test double for module.VulnDetector.
type FakeVulnDetector struct {
	*module.BaseModule
}

// NewFakeVulnDetector creates a new FakeVulnDetector.
// TODO: 456152069 - This function's signature is incomplete. Some tests will have to be updated
// later on.
func NewFakeVulnDetector(name string) *FakeVulnDetector {
	return &FakeVulnDetector{
		BaseModule: module.NewBaseModule(name),
	}
}

// InitFakeVulnDetector return an init function for the FakeVulnDetector. If err is provided, the
// init function will immediately return it.
func InitFakeVulnDetector(name string, err error) module.InitVulnDetectorFn {
	return func(c *config.Config) (module.VulnDetector, error) {
		if err != nil {
			return nil, err
		}

		return NewFakeVulnDetector(name), nil
	}
}
