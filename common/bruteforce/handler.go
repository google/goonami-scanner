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

package bruteforce

import (
	"context"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

// Handler defines the protocol-specific operations required by the generic
// brute-force detector to fingerprint a target service, spawn credential
// workers, and construct the resulting vulnerability finding.
type Handler interface {
	// Name returns the unique module name of the detector.
	Name() string

	// Fingerprint checks whether the target service is running the expected
	// protocol or application before attempting credential brute-forcing.
	// Returning (false, nil) indicates the service does not match and brute-forcing
	// should be skipped without error.
	Fingerprint(ctx context.Context, service *nspb.NetworkService) (bool, error)

	// NewWorker returns a Worker for testing credentials in a single goroutine.
	// Stateless handlers may return themselves if they implement Worker.
	NewWorker() Worker

	// Vulnerability returns the base vulnerability metadata to report when weak
	// credentials are discovered. Must not return nil. The brute-force detector
	// clones this message and populates AdditionalDetails with each discovered
	// weak credential.
	Vulnerability() *vpb.Vulnerability
}
