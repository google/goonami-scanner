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

import (
	"context"

	"github.com/google/goonami-scanner/core/config"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// VulnDetector is a module that can detect vulnerabilities.
type VulnDetector interface {
	// Name of the module. Should be inherited from the BaseModule.
	Name() string

	// Detect the presence of a vulnerability on the network service.
	Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error)
}

// InitVulnDetectorFn is the function signature for initializing a detector module.
type InitVulnDetectorFn func(*config.Config) (VulnDetector, error)
