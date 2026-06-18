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

// Package entrypoint is the actual library entry point to use Goonami.
package entrypoint

import (
	"context"
	"fmt"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/runner"
	"github.com/google/goonami-scanner/core/runner/simplerunner"

	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

// Options are the parameters that control the behavior of the core engine of Goonami.
type Options struct {
	// Config is an already loaded configuration.
	Config *config.Config

	// (Optional) Runner to use. Can be used to more granularly control the behavior of the scan.
	Runner runner.Runner

	// (Optional) Logger to use.
	Logger log.Logger

	// (Optional) HTTPClient is the client that Goonami modules will use to perform HTTP requests.
	HTTPClient goohttp.Client

	// PortScanner is the init function used to create the port scanner module.
	PortScanner module.InitPortScannerFn

	// Fingerprinters are the init functions used to create the fingerprinter modules. Order is
	// important.
	Fingerprinters []module.InitFingerprinterFn

	// Detectors are the init functions used to create the vulnerability detector modules. Order is
	// important.
	Detectors []module.InitVulnDetectorFn
}

// Entrypoint is the entry point to use Goonami.
type Entrypoint struct {
	config *config.Config
	runner runner.Runner
}

// New creates a new Entrypoint.
// Note: Creation of an entrypoint can have side-effects. The general Goonami core provides a
// configurable singleton logger and HTTP client through the use of globals.
func New(ctx context.Context, options *Options) (*Entrypoint, error) {
	ctx = log.ContextForModule(ctx, "entrypoint")
	if options.Config == nil {
		return nil, fmt.Errorf("a config is required")
	}

	if options.Logger != nil {
		log.SetLogger(options.Logger)
		log.InfoContextf(ctx, "the logger was modified")
	}

	var r runner.Runner
	var err error
	if options.Runner == nil {
		if r, err = simplerunner.New(options.Config); err != nil {
			return nil, err
		}
	} else {
		r = options.Runner
	}

	if options.HTTPClient != nil {
		goohttp.SetDefaultClient(options.HTTPClient)
		log.InfoContextf(ctx, "the HTTP client was modified")
	} else {
		if err = goohttp.InitializeDefaults(options.Config); err != nil {
			return nil, err
		}
	}

	module, err := options.PortScanner(ctx, options.Config)
	if err != nil {
		return nil, err
	}
	log.InfoContextf(ctx, "registering port scanner: %s", module.Name())
	r.RegisterPortScanner(ctx, module)

	log.InfoContextf(ctx, "registering %d fingerprinters", len(options.Fingerprinters))
	for _, fingerprinterInit := range options.Fingerprinters {
		module, err := fingerprinterInit(ctx, options.Config)
		if err != nil {
			return nil, err
		}

		r.RegisterFingerprinter(ctx, module)
	}

	log.InfoContextf(ctx, "registering %d vulnerability detectors", len(options.Detectors))
	for _, detectorInit := range options.Detectors {
		module, err := detectorInit(ctx, options.Config)
		if err != nil {
			return nil, err
		}

		r.RegisterDetector(ctx, module)
	}

	log.InfoContextf(ctx, "initializing callback server client")
	if err := callbackserver.Initialize(ctx, options.Config); err != nil {
		return nil, err
	}

	if !callbackserver.DefaultClient().IsCallbackServerEnabled() {
		log.WarnContextf(ctx, "callback server client is not configured, detection relying on it will not work")
	}

	return &Entrypoint{
		config: options.Config,
		runner: r,
	}, nil
}

// Run runs the Goonami scanner.
func (e *Entrypoint) Run(ctx context.Context, target string) (*srpb.ScanResults, error) {
	ctx = log.ContextForModule(ctx, "entrypoint")
	log.InfoContextf(ctx, "running scan for target %q", target)
	return e.runner.Run(ctx, target)
}

// Artifacts returns the directory where artifacts were stored.
func (e *Entrypoint) Artifacts() string {
	return e.config.ArtifactsDirectory()
}
