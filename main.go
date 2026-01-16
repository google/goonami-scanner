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

	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

// The port scanner to use for the scan.
var portScanner = nmap.New

// The list of fingerprinters to use for the scan.
var fingerprinters = []module.InitFingerprinterFn{
	sslsupport.New,
	iswebservice.New,
}

var (
	configFlag     = flag.String("config", "", "path to the configuration file")
	debugLevelFlag = flag.Int("debug", 0, "enable debug logging")
	outputDirFlag  = flag.String("output_dir", "", "directory to write the results and artifacts to")
	targetFlag     = flag.String("target", "", "target to scan")
)

func main() {
	flag.Parse()

	if err := validateFlags(); err != nil {
		log.Errorf("invalid flags: %v", err)
		os.Exit(1)
	}

	log.Infof("initializing the scanner's config")
	cfg, err := config.FromFile(*configFlag)
	if err != nil {
		log.Errorf("failed to load the config: %v", err)
		os.Exit(1)
	}

	if err := cfg.CreateDirectories(*outputDirFlag); err != nil {
		log.Errorf("failed to create the scanner's directories: %v", err)
		os.Exit(1)
	}
	defer cfg.Close()

	logger := &log.DefaultLogger{VerboseLevel: log.DebugLevel(*debugLevelFlag)}

	log.Infof("initializing the scanner's entrypoint")
	options := &entrypoint.Options{
		Config:         cfg,
		Logger:         logger,
		PortScanner:    portScanner,
		Fingerprinters: fingerprinters,
	}

	entrypoint, err := entrypoint.New(options)
	if err != nil {
		log.Errorf("failed to create the entrypoint: %v", err)
		os.Exit(1)
	}

	log.Infof("running the scanner")
	ctx := context.Background()
	results, err := entrypoint.Run(ctx, *targetFlag)
	if err != nil {
		log.Errorf("failed to run the scanner: %v", err)
		os.Exit(1)
	}

	// note: we dissociate the scan results from the other artifacts.
	resultsPath := path.Join(cfg.WorkingDirectory(), "results.textproto")
	log.Infof("writing results to %q", resultsPath)
	if err := writeResults(resultsPath, results); err != nil {
		log.Errorf("failed to write results to %q: %v", resultsPath, err)
		os.Exit(1)
	}

	log.Infof("results written to %q", resultsPath)
}

func validateFlags() error {
	if *targetFlag == "" {
		return fmt.Errorf("a --target is required")
	}

	if *outputDirFlag == "" {
		return fmt.Errorf("an --output_dir is required")
	}

	if *configFlag == "" {
		return fmt.Errorf("a --config is required")
	}

	if *debugLevelFlag < 0 || *debugLevelFlag > 3 {
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
