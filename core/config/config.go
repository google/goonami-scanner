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
	"context"
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

var (
	// ErrUninitialized is returned when a method is called before the configuration is initialized.
	// This happens if `CreateDirectories` was never called.
	ErrUninitialized = errors.New("configuration was never initialized with CreateDirectories()")

	// ErrWorkDirEmpty is returned when the working directory is empty.
	ErrWorkDirEmpty = errors.New("working directory is empty")

	// ErrWorkDirAccess is returned when there is an error while accessing the working directory.
	ErrWorkDirAccess = errors.New("error while accessing working directory")

	// ErrCreateDir is returned when there is an error while creating a directory.
	ErrCreateDir = errors.New("error while creating directory")

	// ErrConfigRead is returned when there is an error while reading the configuration file.
	ErrConfigRead = errors.New("error while reading configuration file")

	// ErrConfigUnmarshal is returned when there is an error while unmarshaling the configuration.
	ErrConfigUnmarshal = errors.New("error while unmarshaling configuration")

	// ErrInvalidOverrideFormat is returned when the override format is invalid.
	ErrInvalidOverrideFormat = errors.New("invalid override format")

	// ErrFieldNotFound is returned when a configuration field is not found.
	ErrFieldNotFound = errors.New("configuration field not found")

	// ErrFieldNotMessage is returned when a configuration field is not a message.
	ErrFieldNotMessage = errors.New("configuration field is not a message")

	// ErrUnsupportedFieldKind is returned when a configuration field kind is not supported.
	ErrUnsupportedFieldKind = errors.New("unsupported configuration field kind")
)

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
	cacheDir     string
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
				MaxHttpRedirects:         proto.Int32(10),
			}.Build(),
		}.Build(),
	}.Build()
}

// FromFile creates a new Config from a textproto file. Caller is still responsible for explicitly
// calling `CreateDirectories` before using the configuration.
func FromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigRead, err)
	}

	cfgpb := DefaultProto()
	provided := &cpb.Config{}
	if err := prototext.Unmarshal(data, provided); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
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
		return ErrWorkDirEmpty
	}

	if _, err := os.Stat(workdir); err != nil {
		return fmt.Errorf("%w %q: %v", ErrWorkDirAccess, workdir, err)
	}

	c.workDir = workdir
	c.tempDir = path.Join(c.workDir, "tempfiles")
	if err := os.MkdirAll(c.tempDir, 0700); err != nil {
		return fmt.Errorf("%w %q: %v", ErrCreateDir, c.tempDir, err)
	}

	c.artifactsDir = path.Join(c.workDir, "artifacts")
	if err := os.MkdirAll(c.artifactsDir, 0700); err != nil {
		return fmt.Errorf("%w %q: %v", ErrCreateDir, c.artifactsDir, err)
	}

	c.cacheDir = path.Join(c.workDir, "cache")
	if err := os.MkdirAll(c.cacheDir, 0700); err != nil {
		return fmt.Errorf("%w %q: %v", ErrCreateDir, c.cacheDir, err)
	}

	return nil
}

// Close ensures proper clean-up is performed.
func (c *Config) Close(ctx context.Context) error {
	ctx = log.ContextForModule(ctx, "core/config")
	if c.tempDir == "" {
		log.WarnContext(ctx, "Clean-up could not be performed. Configuration was never Initialized.")
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

// WorkflowConfig returns the configuration options that are specific to workflow execution.
func (c *Config) WorkflowConfig() *cpb.WorkflowConfiguration {
	return c.proto.GetWorkflowcfg()
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

// CacheDirectory returns the path to the cache directory.
func (c *Config) CacheDirectory() string {
	return c.cacheDir
}

// GetCacheForModule returns the path to the cache directory for the given module,
// creating it if it does not exist.
func (c *Config) GetCacheForModule(moduleName string) (string, error) {
	if c.cacheDir == "" {
		return "", ErrUninitialized
	}
	dir := path.Join(c.cacheDir, moduleName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("%w %q: %v", ErrCreateDir, dir, err)
	}
	return dir, nil
}
