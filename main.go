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

// Package main provides a binary entrypoint for Goonami.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/entrypoint"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/encoding/prototext"

	// port scanner plugins
	"github.com/google/goonami-scanner/plugins/portscan/nmap"

	// fingerprinters
	"github.com/google/goonami-scanner/plugins/fingerprint/iswebservice"
	"github.com/google/goonami-scanner/plugins/fingerprint/sslsupport"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity"

	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

// The port scanner to use for the scan.
var portScanner = nmap.New

// The list of fingerprinters to use for the scan.
var fingerprinters = []module.InitFingerprinterFn{
	sslsupport.New,
	iswebservice.New,

	// note: keep last. The webidentity plugin can fork the existing list of service. For efficiency,
	// it should be the last plugin in the list.
	webidentity.New,
}

var (
	// ConfigFlag controls the path to the configuration file of the scanner.
	ConfigFlag = flag.String("config", "", "path to the configuration file")
	// DebugLevelFlag controls the level of debug logs to show.
	DebugLevelFlag = flag.Int("debug", 0, "enable debug logging")
	// OutputDirFlag controls the directory to write the results and artifacts to.
	OutputDirFlag = flag.String("output_dir", "", "directory to write the results and artifacts to")
	// TargetFlag controls the target to scan.
	TargetFlag = flag.String("target", "", "target to scan")
)

func main() {
	flag.Parse()

	if err := run(context.Background()); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if err := validateFlags(); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	log.Infof("initializing the scanner's config")
	cfg, err := config.FromFile(*ConfigFlag)
	if err != nil {
		return fmt.Errorf("failed to load the config: %w", err)
	}

	if err := cfg.CreateDirectories(*OutputDirFlag); err != nil {
		return fmt.Errorf("failed to create the scanner's directories: %w", err)
	}
	defer cfg.Close()

	logger := &log.DefaultLogger{VerboseLevel: log.DebugLevel(*DebugLevelFlag)}

	log.Infof("initializing the scanner's entrypoint")
	options := &entrypoint.Options{
		Config:         cfg,
		Logger:         logger,
		PortScanner:    portScanner,
		Fingerprinters: fingerprinters,
	}

	e, err := entrypoint.New(options)
	if err != nil {
		return fmt.Errorf("failed to create the entrypoint: %w", err)
	}

	log.Infof("running the scanner")
	results, err := e.Run(ctx, *TargetFlag)
	if err != nil {
		return fmt.Errorf("failed to run the scanner: %w", err)
	}

	// note: we dissociate the scan results from the other artifacts.
	resultsPath := path.Join(cfg.WorkingDirectory(), "results.textproto")
	log.Infof("writing results to %q", resultsPath)
	if err := writeResults(resultsPath, results); err != nil {
		return fmt.Errorf("failed to write results to %q: %w", resultsPath, err)
	}

	log.Infof("results written to %q", resultsPath)
	return nil
}

func validateFlags() error {
	if *TargetFlag == "" {
		return fmt.Errorf("a --target is required")
	}

	if *OutputDirFlag == "" {
		return fmt.Errorf("an --output_dir is required")
	}

	if *ConfigFlag == "" {
		return fmt.Errorf("a --config is required")
	}

	if *DebugLevelFlag < 0 || *DebugLevelFlag > 3 {
		return fmt.Errorf("--debug must be between 0 (no debug) and 3 (all debug logs)")
	}

	return nil
}

func writeResults(resultsPath string, results *srpb.ScanResults) error {
	options := prototext.MarshalOptions{Multiline: true}
	textproto, err := options.Marshal(results)
	if err != nil {
		return err
	}

	return os.WriteFile(resultsPath, textproto, 0644)
}
