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

// Package nmap instruments the nmap scanner.
package nmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/net/iputils"
	"google.golang.org/protobuf/proto"

	nccpb "github.com/google/goonami-scanner/common/clients/nmap/nmap_client_config_go_proto"
)

var (
	// ErrInvalidTechnique is returned when the port scan technique is invalid.
	ErrInvalidTechnique = errors.New("invalid port scan technique")

	// ErrNmapExecution is returned when nmap fails to execute.
	ErrNmapExecution = errors.New("nmap execution failed")

	// ErrNmapOutputRead is returned when there is an error while reading nmap output.
	ErrNmapOutputRead = errors.New("error while reading nmap output")

	// ErrNmapXMLUnmarshal is returned when there is an error while unmarshalling nmap XML output.
	ErrNmapXMLUnmarshal = errors.New("error while unmarshalling nmap XML output")

	// ErrNmapTempFile is returned when there is an error with the nmap temporary file.
	ErrNmapTempFile = errors.New("error with nmap temporary file")
)

// DefaultConfig for the nmap client.
// TCP scan of intensity 3 without version detection or scripts. No host discovery (-Pn option).
func DefaultConfig() *nccpb.NmapClientConfig {
	return nccpb.NmapClientConfig_builder{
		TimeoutSeconds:         proto.Int32(300),
		ScanTechnique:          nccpb.NmapClientConfig_CONNECT.Enum(),
		ScanIntensity:          proto.Uint32(3),
		EnableHostDiscovery:    proto.Bool(false),
		EnableVersionDetection: proto.Bool(false),
	}.Build()
}

// Client is the interface of the nmap client. We define an interface as we also provide a fake
// implementation for testing.
type Client interface {
	Run(ctx context.Context, target string) (*OutputXML, error)
}

// SimpleClient instrumenting nmap.
type SimpleClient struct {
	config     *nccpb.NmapClientConfig
	coreConfig *config.Config
}

// New nmap client.
func New(cfg *config.Config) *SimpleClient {
	nmapCfg := DefaultConfig()
	if cfg.ClientsConfig().HasNmap() {
		proto.Merge(nmapCfg, cfg.ClientsConfig().GetNmap())
	}

	return &SimpleClient{
		coreConfig: cfg,
		config:     nmapCfg,
	}
}

// CommandLine used to run nmap.
func (c *SimpleClient) CommandLine(ctx context.Context, target string) ([]string, error) {
	ctx = log.ContextForModule(ctx, "client/nmap")
	return c.buildOpts(ctx, target, "")
}

// Run nmap and returns the parsed XML output.
func (c *SimpleClient) Run(ctx context.Context, target string) (*OutputXML, error) {
	scanCtx := ctx
	if c.config.GetTimeoutSeconds() > 0 {
		var cancel context.CancelFunc
		duration := time.Duration(c.config.GetTimeoutSeconds()) * time.Second
		scanCtx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}

	outputFile, err := c.createOutputFile(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNmapTempFile, err)
	}
	defer os.Remove(outputFile)

	ctx = log.ContextForModule(ctx, "client/nmap")
	args, err := c.buildOpts(ctx, target, outputFile)
	if err != nil {
		return nil, err
	}

	binaryPath := c.config.GetBinaryPath()
	if binaryPath == "" {
		binaryPath = "nmap"
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "running %q with args: %v", binaryPath, args)
	cmd := exec.CommandContext(scanCtx, binaryPath, args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNmapExecution, err)
	}

	output, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNmapOutputRead, err)
	}

	return ParseXMLOutput(output)
}

func (c *SimpleClient) createOutputFile(ctx context.Context) (string, error) {
	tmpFile, err := os.CreateTemp("", "nmap-*.xml")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNmapTempFile, err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("%w: %v", ErrNmapTempFile, err)
	}

	return tmpFile.Name(), nil
}

func (c *SimpleClient) optPorts() string {
	// if no ports are specified, we scan all ports.
	ports := c.coreConfig.GlobalConfig().GetPortsToScan()
	if len(ports) == 0 {
		return "-p-"
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(int(p)))
	}

	return "-p" + strings.Join(portStrs, ",")
}

func (c *SimpleClient) optTechnique() (string, error) {
	switch c.config.GetScanTechnique() {
	case nccpb.NmapClientConfig_CONNECT:
		return "-sT", nil
	case nccpb.NmapClientConfig_UDP:
		return "-sU", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidTechnique, c.config.GetScanTechnique().String())
	}
}

func (c *SimpleClient) optHostDiscovery() string {
	if !c.config.GetEnableHostDiscovery() {
		return "-Pn"
	}

	return ""
}

func (c *SimpleClient) optVersionDetection(ctx context.Context) []string {
	if !c.config.GetEnableVersionDetection() {
		return nil
	}

	args := []string{"-sV"}

	if c.config.GetVersionIntensity() == 0 {
		return args
	}

	if c.config.GetVersionIntensity() > 9 {
		log.WarnContextf(ctx, "version intensity %d is invalid, defaulting to 5", c.config.GetVersionIntensity())
		c.config.SetVersionIntensity(5)
	}

	args = append(args, "--version-intensity")
	args = append(args, strconv.Itoa(int(c.config.GetVersionIntensity())))
	return args
}

func (c *SimpleClient) optScripts() []string {
	var args []string

	userAgent := c.coreConfig.GlobalConfig().GetUserAgent()
	if userAgent != "" {
		option := "http.useragent=" + userAgent
		args = append(args, "--script-args", option)
	}

	if c.config.GetEnableHttpMethodsDetection() {
		args = append(args, "--script", "http-methods")
	}

	if c.config.GetEnableSslDetection() {
		args = append(args, "--script", "ssl-cert")
		args = append(args, "--script", "ssl-enum-ciphers")
	}

	return args
}

func (c *SimpleClient) optIPVersion(target string) string {
	if iputils.IsIPv6(target) {
		return "-6"
	}

	return ""
}

func (c *SimpleClient) optPerformance(ctx context.Context) []string {
	var args []string

	qps := c.coreConfig.GlobalConfig().GetPerformance().GetMaxPacketsPerSecond()
	if qps > 0 {
		args = append(args, "--max-rate")
		args = append(args, strconv.Itoa(int(qps)))
	}

	intensity := c.config.GetScanIntensity()
	if intensity <= 0 || intensity > 5 {
		log.WarnContextf(ctx, "invalid scan intensity: %d, defaulting to 3", c.config.GetScanIntensity())
		intensity = 3
	}

	args = append(args, fmt.Sprintf("-T%d", intensity))
	return args
}

func (c *SimpleClient) buildOpts(ctx context.Context, target string, outputFile string) ([]string, error) {
	mode, err := c.optTechnique()
	if err != nil {
		return nil, err
	}

	output := []string{"-oX", outputFile}
	output = append(output, mode)
	output = append(output, c.optPerformance(ctx)...)
	output = append(output, c.optIPVersion(target))
	output = append(output, c.optPorts())
	output = append(output, c.optHostDiscovery())
	output = append(output, c.optVersionDetection(ctx)...)
	output = append(output, c.optScripts()...)
	output = append(output, target)
	return output, nil
}
