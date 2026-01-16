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

package module

import "github.com/google/goonami-scanner/core/config"

// VulnDetector is a module that can detect vulnerabilities.
type VulnDetector interface {
	// Name of the module. Should be inherited from the BaseModule.
	Name() string

	// TODO: b/456152069 - To be implemented. Will probably take a NetworkService as input and return
	// a set of vulnerabilities.
}

// InitVulnDetectorFn is the function signature for initializing a detector module.
type InitVulnDetectorFn func(*config.Config) (VulnDetector, error)
