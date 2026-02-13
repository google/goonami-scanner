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

// Package config provides utilities to load and parse the Goonami config.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/google/goonami-scanner/core/log"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

// ErrUninitialized is returned when a method is called before the configuration is initialized.
// This happens if `CreateDirectories` was never called.
var ErrUninitialized = errors.New("configuration was never initialized with CreateDirectories()")

// Config is the configuration used by Goonami. It holds configuration for clients, plugins and
// options that are global to the scanner. It also keeps track of a set of directories used by the
// scanner to write files to.
//
// The recommended way to use config is:
//
// cfg, err := config.FromFile(path)
// if err != nil { handle errors }
//
// cfg.CreateDirectories(workdir)
// if err != nil { handle errors }
//
// defer cfg.Close()
//
// Then you can use the configuration
type Config struct {
	proto        *cpb.Config
	workDir      string
	tempDir      string
	artifactsDir string
}

// DefaultProto returns the default configuration for Goonami.
func DefaultProto() *cpb.Config {
	return cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			Performance: cpb.GlobalConfig_Performance_builder{
				MaxConcurrency:           proto.Int32(5),
				TimeoutPerRequestSeconds: proto.Int32(10),
				MaxPacketsPerSecond:      proto.Int32(0),
				MaxHttpRequestsPerSecond: proto.Int32(0),
			}.Build(),
		}.Build(),
	}.Build()
}

// FromFile creates a new Config from a textproto file. Caller is still responsible for explicitly
// calling `CreateDirectories` before using the configuration.
func FromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfgpb := DefaultProto()
	provided := &cpb.Config{}
	if err := prototext.Unmarshal(data, provided); err != nil {
		return nil, err
	}
	proto.Merge(cfgpb, provided)

	return &Config{
		proto: cfgpb,
	}, nil
}

// FromProto creates a new Config from a Config proto. Caller is still responsible for explicitly
// calling `CreateDirectories` before using the configuration.
func FromProto(cfgpb *cpb.Config) *Config {
	merged := DefaultProto()
	proto.Merge(merged, cfgpb)
	return &Config{
		proto: merged,
	}
}

// Default creates a new Config with the default configuration.
func Default() *Config {
	return &Config{
		proto: DefaultProto(),
	}
}

// CreateDirectories that are used by the scanner throughout its execution. This method MUST be
// called before using the configuration as it makes a set of directories available to the scanner
// and its plugins.
func (c *Config) CreateDirectories(workdir string) error {
	if workdir == "" {
		return fmt.Errorf("working directory is empty")
	}

	if _, err := os.Stat(workdir); err != nil {
		return fmt.Errorf("error while accessing working directory %q: %w", workdir, err)
	}

	c.workDir = workdir
	c.tempDir = path.Join(c.workDir, "tempfiles")
	if err := os.MkdirAll(c.tempDir, 0700); err != nil {
		return err
	}

	c.artifactsDir = path.Join(c.workDir, "artifacts")
	if err := os.MkdirAll(c.artifactsDir, 0700); err != nil {
		return err
	}

	return nil
}

// Close ensures proper clean-up is performed.
func (c *Config) Close() error {
	if c.tempDir == "" {
		log.Warn("Clean-up could not be performed. Configuration was never Initialized.")
		return ErrUninitialized
	}

	return os.RemoveAll(c.tempDir)
}

// GlobalConfig returns configuration options that are global.
func (c *Config) GlobalConfig() *cpb.GlobalConfig {
	return c.proto.GetGlobalcfg()
}

// ClientsConfig returns configuration options that are specific to clients.
func (c *Config) ClientsConfig() *cpb.ClientsConfig {
	return c.proto.GetClients()
}

// PluginsConfig returns the configuration options that are specific to plugins.
func (c *Config) PluginsConfig() *cpb.PluginsConfig {
	return c.proto.GetPlugins()
}

// WorkingDirectory that the scanner is using to write files to.
func (c *Config) WorkingDirectory() string {
	return c.workDir
}

// TempDirectory that the scanner is using to write temporary files to.
func (c *Config) TempDirectory() string {
	return c.tempDir
}

// ArtifactsDirectory that the scanner is using to write files that will be available after the
// scan (artifacts).
func (c *Config) ArtifactsDirectory() string {
	return c.artifactsDir
}

// TimeoutPerRequest is a helper that returns the timeout set in the global configuration.
func (c *Config) TimeoutPerRequest() time.Duration {
	return time.Duration(c.GlobalConfig().GetPerformance().GetTimeoutPerRequestSeconds()) * time.Second
}
