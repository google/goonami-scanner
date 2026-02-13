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

// Package runner provides orchestration for Goonami modules.
package runner

import (
	"context"

	"github.com/google/goonami-scanner/core/module"

	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

// Runner is an orchestrator that defines how to run Goonami modules.
type Runner interface {
	RegisterPortScanner(context.Context, module.PortScanner) error
	RegisterFingerprinter(context.Context, module.Fingerprinter) error
	RegisterDetector(context.Context, module.VulnDetector) error

	Run(context.Context, string) (*srpb.ScanResults, error)
}
