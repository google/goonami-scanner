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

// Package iswebservice provides a fingerprinter to define if a network service is a web service.
package iswebservice

import (
	"context"
	"net/http"
	"slices"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const (
	moduleName = "fp/iswebservice"
)

// Module is the fingerprinter to detect if a network service is a web service.
type Module struct {
	*module.BaseModule
	config *config.Config
}

// New returns a new instance of the module.
func New(config *config.Config) (module.Fingerprinter, error) {
	return &Module{
		BaseModule: module.NewBaseModule(moduleName),
		config:     config,
	}, nil
}

// Fingerprint provides in-place enrichment of a network service through fingerprinting.
func (m *Module) Fingerprint(ctx context.Context, service *nspb.NetworkService) error {
	webroot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, m.config.TimeoutPerRequest())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", webroot, nil)
	if err != nil {
		return err
	}

	// If the request failed, this is not a web service but not an issue.
	resp, err := goohttp.DefaultClient().Do(req)
	if err != nil {
		log.Debugf(log.DebugLevelService, "[fp/iswebservice] %q is not a web service", webroot)
		return nil
	}
	defer resp.Body.Close()

	log.Debugf(log.DebugLevelService, "[fp/iswebservice] %q is a web service", webroot)
	if !slices.Contains(service.GetSupportedHttpMethods(), "GET") {
		supported := append(service.GetSupportedHttpMethods(), "GET")
		service.SetSupportedHttpMethods(supported)
	}

	return nil
}
