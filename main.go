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
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/entrypoint"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"github.com/google/goonami-scanner/tools/callbackserver"
	"google.golang.org/protobuf/encoding/prototext"

	// HTTP clients
	_ "github.com/google/goonami-scanner/core/net/http/simpleclient"

	// port scanner plugins
	_ "github.com/google/goonami-scanner/plugins/portscan/httpscan"
	_ "github.com/google/goonami-scanner/plugins/portscan/nmap"
	_ "github.com/google/goonami-scanner/plugins/portscan/noop"

	// fingerprinters
	_ "github.com/google/goonami-scanner/plugins/fingerprint/iswebservice"
	_ "github.com/google/goonami-scanner/plugins/fingerprint/sslsupport"
	_ "github.com/google/goonami-scanner/plugins/fingerprint/webidentity"

	// detectors
	_ "github.com/google/goonami-scanner/plugins/detectors/adkweakcreds"
	_ "github.com/google/goonami-scanner/plugins/detectors/opensshauthbypass"
	_ "github.com/google/goonami-scanner/plugins/detectors/templated"
	_ "github.com/google/goonami-scanner/plugins/detectors/templatedweakcredentials"
	_ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/mysql"
	_ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/postgres"
	_ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/ssh"

	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
	srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
	vulnpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

var (
	// ErrTargetRequired is returned when the target flag is missing.
	ErrTargetRequired = errors.New("a --target is required")

	// ErrOutputDirRequired is returned when the output_dir flag is missing.
	ErrOutputDirRequired = errors.New("an --output_dir is required")

	// ErrConfigRequired is returned when the config flag is missing.
	ErrConfigRequired = errors.New("a --config is required")

	// ErrInvalidDebugLevel is returned when the debug flag is invalid.
	ErrInvalidDebugLevel = errors.New("--debug must be between 0 (no debug) and 3 (all debug logs)")

	// ErrMarshalResults is returned when the scan results cannot be marshaled.
	ErrMarshalResults = errors.New("failed to marshal scan results")

	// ErrWriteResults is returned when the scan results cannot be written to a file.
	ErrWriteResults = errors.New("failed to write scan results to file")

	// ErrMarshalAdvisories is returned when the advisories list cannot be marshaled.
	ErrMarshalAdvisories = errors.New("failed to marshal advisories")

	// ErrWriteAdvisories is returned when the advisories list cannot be written to a file.
	ErrWriteAdvisories = errors.New("failed to write advisories to file")
)

var (
	// ConfigFlag controls the path to the configuration file of the scanner.
	ConfigFlag = flag.String("config", "", "path to the configuration file")
	// DebugLevelFlag controls the level of debug logs to show.
	DebugLevelFlag = flag.Int("debug", 0, "enable debug logging")
	// OutputDirFlag controls the directory to write the results and artifacts to.
	OutputDirFlag = flag.String("output_dir", "", "directory to write the results and artifacts to")
	// TargetFlag controls the target to scan.
	TargetFlag = flag.String("target", "", "target to scan")
	// ColorFlag controls whether to use colors in the output.
	ColorFlag = flag.Bool("color", true, "use colors in the output")
	// OverridesFlag allows overriding specific options from the configuration file.
	OverridesFlag = stringSlice("o", "override configuration options (format: key=value)")
	// MetricsFlag controls whether the scan collects metrics and writes them to
	// metrics.textproto in the output directory.
	MetricsFlag = flag.Bool("metrics", false, "collect scan metrics and write them to metrics.textproto")
	// AdvisoriesFlag controls the file path to dump supported advisories to, skipping scan execution.
	AdvisoriesFlag = flag.String("advisories", "", "dump the list of supported advisories to the given file in textproto format and exit")
)

func stringSlice(name, usage string) *[]string {
	var p []string
	flag.Func(name, usage, func(s string) error {
		p = append(p, s)
		return nil
	})
	return &p
}

func main() {
	flag.Parse()
	ctx := log.ContextForModule(context.Background(), "main")

	if err := run(ctx); err != nil {
		log.ErrorContextf(ctx, "%v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if err := validateFlags(); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	logger := &log.DefaultLogger{
		VerboseLevel: log.DebugLevel(*DebugLevelFlag),
		UseColors:    *ColorFlag,
	}

	if *AdvisoriesFlag != "" {
		return dumpAdvisories(ctx, logger, *AdvisoriesFlag)
	}

	log.InfoContextf(ctx, "initializing the scanner's config from %q", *ConfigFlag)
	cfg, err := config.FromFile(*ConfigFlag)
	if err != nil {
		return fmt.Errorf("failed to load the config: %w", err)
	}

	if err := cfg.ApplyOverrides(ctx, *OverridesFlag); err != nil {
		return fmt.Errorf("failed to apply configuration overrides: %w", err)
	}

	if err := cfg.CreateDirectories(*OutputDirFlag); err != nil {
		return fmt.Errorf("failed to create the scanner's directories: %w", err)
	}
	defer cfg.Close(ctx)

	log.InfoContextf(ctx, "initializing the scanner's entrypoint")
	options := &entrypoint.Options{
		Config: cfg,
		Logger: logger,
	}

	var collector *metrics.Collector
	if *MetricsFlag {
		collector = metrics.NewCollector()
		options.Recorder = collector
	}

	e, err := entrypoint.New(ctx, options)
	if err != nil {
		return fmt.Errorf("failed to create the entrypoint: %w", err)
	}

	log.InfoContextf(ctx, "starting the callback server")
	srv, err := startCallbackServer(ctx, cfg.ClientsConfig().GetCallbackServer())
	if err != nil {
		return fmt.Errorf("failed to start the callback server: %w", err)
	}
	defer srv.Shutdown(ctx)

	log.InfoContextf(ctx, "running the scanner")
	results, err := e.Run(ctx, *TargetFlag)

	// Write the metrics unconditionally of the scan success.
	writeMetrics(ctx, collector, cfg.WorkingDirectory())

	if err != nil {
		return fmt.Errorf("failed to run the scanner: %w", err)
	}

	// note: we dissociate the scan results from the other artifacts.
	resultsPath := path.Join(cfg.WorkingDirectory(), "results.textproto")
	if err := writeResults(resultsPath, results); err != nil {
		return fmt.Errorf("failed to write results to %q: %w", resultsPath, err)
	}

	log.InfoContextf(ctx, "results written to %q", resultsPath)
	return nil
}

func writeMetrics(ctx context.Context, collector *metrics.Collector, dir string) {
	if collector == nil {
		return
	}

	metricsPath := path.Join(dir, "metrics.textproto")
	if err := collector.WriteFile(metricsPath); err != nil {
		log.ErrorContextf(ctx, "failed to write metrics to %q: %v", metricsPath, err)
		return
	}
	log.InfoContextf(ctx, "metrics written to %q", metricsPath)
}

func validateFlags() error {
	if *DebugLevelFlag < 0 || *DebugLevelFlag > 3 {
		return ErrInvalidDebugLevel
	}

	if *AdvisoriesFlag != "" {
		return nil
	}

	if *TargetFlag == "" {
		return ErrTargetRequired
	}

	if *OutputDirFlag == "" {
		return ErrOutputDirRequired
	}

	if *ConfigFlag == "" {
		return ErrConfigRequired
	}

	return nil
}

func dumpAdvisories(ctx context.Context, logger log.Logger, advisoriesPath string) error {
	log.SetLogger(logger)
	log.InfoContextf(ctx, "no scan will be performed, dumping advisories to %q", advisoriesPath)

	advisories, err := entrypoint.Advisories(ctx, nil)
	if err != nil {
		return fmt.Errorf("collecting advisories: %w", err)
	}

	if err := writeAdvisories(advisoriesPath, advisories); err != nil {
		return err
	}

	log.InfoContextf(ctx, "advisories written to %q", advisoriesPath)
	return nil
}

func writeAdvisories(advisoriesPath string, advisories *vulnpb.VulnerabilityList) error {
	options := prototext.MarshalOptions{Multiline: true}
	textproto, err := options.Marshal(advisories)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalAdvisories, err)
	}

	if err := os.WriteFile(advisoriesPath, textproto, 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteAdvisories, err)
	}
	return nil
}

func startCallbackServer(ctx context.Context, cfg *cbpb.CallbackserverConfig) (*callbackserver.Server, error) {
	srv, err := callbackserver.New(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err := srv.StartPolling(ctx); err != nil {
		return nil, err
	}

	if err := srv.StartRecordingHTTP(ctx); err != nil {
		return nil, err
	}

	if err := srv.StartRecordingDNS(ctx); err != nil {
		return nil, err
	}

	return srv, nil
}

func writeResults(resultsPath string, results *srpb.ScanResults) error {
	options := prototext.MarshalOptions{Multiline: true}
	textproto, err := options.Marshal(results)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarshalResults, err)
	}

	if err := os.WriteFile(resultsPath, textproto, 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrWriteResults, err)
	}
	return nil
}
