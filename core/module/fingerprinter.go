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

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// Fingerprinter is a module that can fingerprint a target based on the port scanning results.
type Fingerprinter interface {
	// Name of the module. Should be inherited from the BaseModule.
	Name() string

	// Fingerprint tries to provide more information out of a network service. For example, does the
	// service support SSL? Does it run HTTP? It returns a list of network services with enriched
	// information. Note: You might be wondering: why a list when only one service come as input?
	// For historical reasons, Tsunami fingerprinters can "split" a single service if it contains
	// several identified software (e.g. wordpress on one root and drupal on another).
	Fingerprint(ctx context.Context, service *nspb.NetworkService) ([]*nspb.NetworkService, error)
}

// InitFingerprinterFn is the function signature for initializing a fingerprinter module.
type InitFingerprinterFn func(*config.Config) (Fingerprinter, error)
