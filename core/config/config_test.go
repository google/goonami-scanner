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

package config

import (
	"errors"
	"os"
	"path"
	"testing"
	"time"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	validConfig   = "testdata/valid.textproto"
	invalidConfig = "testdata/invalid.textproto"
)

func TestFromFile(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "when_config_is_valid_returns_no_error",
			path:    validConfig,
			wantErr: false,
		},
		{
			name:    "when_config_is_invalid_returns_error",
			path:    invalidConfig,
			wantErr: true,
		},
		{
			name:    "when_file_not_found_returns_error",
			path:    "not/existing/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromFile(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateDirectories(t *testing.T) {
	tests := []struct {
		name string
		// setup is a function run before CreateDirectories() is called. It returns the working
		// directory that should be passed to CreateDirectories().
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "when_workdir_is_valid_creates_all_directories",
			setup: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			wantErr: false,
		},
		{
			name: "when_workdir_is_empty_returns_error",
			setup: func(t *testing.T) string {
				t.Helper()
				return ""
			},
			wantErr: true,
		},
		{
			name: "when_tempdir_creation_fails_because_file_exists_returns_error",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				if err := os.WriteFile(path.Join(dir, "tempfiles"), []byte(""), 0644); err != nil {
					t.Fatalf("cannot create tempfiles file: %v", err)
				}
				return dir
			},
			wantErr: true,
		},
		{
			name: "when_workdir_does_not_exist_returns_error",
			setup: func(t *testing.T) string {
				t.Helper()
				return path.Join("path", "to", "a", "non-existing", "directory")
			},
			wantErr: true,
		},
		{
			name: "when_artifactsdir_creation_fails_because_file_exists_returns_error",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				if err := os.WriteFile(path.Join(dir, "artifacts"), []byte(""), 0644); err != nil {
					t.Fatalf("cannot create artifacts file: %v", err)
				}
				return dir
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := FromFile(validConfig)
			if err != nil {
				t.Fatalf("Failed to load config for test: %v", err)
			}

			workDir := tt.setup(t)

			if err = cfg.CreateDirectories(workDir); (err != nil) != tt.wantErr {
				t.Errorf("CreateDirectories() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if _, err := os.Stat(cfg.WorkingDirectory()); err != nil {
				t.Errorf("Working directory %q not created: %v", cfg.WorkingDirectory(), err)
			}
			if _, err := os.Stat(cfg.TempDirectory()); err != nil {
				t.Errorf("Temp directory %q not created: %v", cfg.TempDirectory(), err)
			}
			if _, err := os.Stat(cfg.ArtifactsDirectory()); err != nil {
				t.Errorf("Artifacts directory %q not created: %v", cfg.ArtifactsDirectory(), err)
			}
		})
	}
}

func TestClose(t *testing.T) {
	tests := []struct {
		name       string
		initialize bool
		wantErr    error
	}{
		{
			name:       "when_config_is_initialized_close_removes_tempdir",
			initialize: true,
			wantErr:    nil,
		},
		{
			name:       "when_config_is_uninitialized_close_returns_error",
			initialize: false,
			wantErr:    ErrUninitialized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := FromFile(validConfig)
			if err != nil {
				t.Fatalf("Failed to load config for test: %v", err)
			}

			if tt.initialize {
				if err := cfg.CreateDirectories(t.TempDir()); err != nil {
					t.Fatalf("Failed to create directories: %v", err)
				}
			}

			tempDir := cfg.TempDirectory()
			if err = cfg.Close(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Close() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.initialize && tt.wantErr == nil {
				if _, err := os.Stat(tempDir); err == nil || !errors.Is(err, os.ErrNotExist) {
					t.Errorf("Temp directory %s not removed after Close()", tempDir)
				}
			}
		})
	}
}

func TestWorkingDirectoryIsCorrect(t *testing.T) {
	workDir := t.TempDir()
	cfg, err := FromFile(validConfig)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.CreateDirectories(workDir); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}
	defer cfg.Close()

	if got := cfg.WorkingDirectory(); got != workDir {
		t.Errorf("WorkingDirectory() = %v, want %v", got, workDir)
	}
}

func TestTempDirectoryIsCorrect(t *testing.T) {
	workDir := t.TempDir()
	cfg, err := FromFile(validConfig)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.CreateDirectories(workDir); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}
	defer cfg.Close()

	want := path.Join(workDir, "tempfiles")
	if got := cfg.TempDirectory(); got != want {
		t.Errorf("TempDirectory() = %v, want %v", got, want)
	}
}

func TestArtifactsDirectoryIsCorrect(t *testing.T) {
	workDir := t.TempDir()
	cfg, err := FromFile(validConfig)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.CreateDirectories(workDir); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}
	defer cfg.Close()

	want := path.Join(workDir, "artifacts")
	if got := cfg.ArtifactsDirectory(); got != want {
		t.Errorf("ArtifactsDirectory() = %v, want %v", got, want)
	}
}

func TestTimeoutPerRequest(t *testing.T) {
	cfg, err := FromFile(validConfig)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.CreateDirectories(t.TempDir()); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}
	defer cfg.Close()

	if got, want := cfg.TimeoutPerRequest(), 30*time.Second; got != want {
		t.Errorf("TimeoutPerRequest() = %v, want %v", got, want)
	}
}

func TestFromProto(t *testing.T) {
	input := cpb.Config_builder{
		Globalcfg: cpb.GlobalConfig_builder{
			UserAgent: proto.String("test-agent"),
		}.Build(),
	}.Build()
	cfg := FromProto(input)

	if cfg.GlobalConfig().GetUserAgent() != "test-agent" {
		t.Errorf("FromProto() did not set UserAgent correctly: got %q, want %q", cfg.GlobalConfig().GetUserAgent(), "test-agent")
	}
	// Check that defaults are also present
	if cfg.GlobalConfig().GetPerformance().GetMaxConcurrency() != 5 {
		t.Errorf("FromProto() did not merge defaults: MaxConcurrency = %d, want 1", cfg.GlobalConfig().GetPerformance().GetMaxConcurrency())
	}
}

func TestGlobalConfig(t *testing.T) {
	want := cpb.GlobalConfig_builder{UserAgent: proto.String("test-agent")}.Build()
	cfg := FromProto(cpb.Config_builder{Globalcfg: want}.Build())

	if got := cfg.GlobalConfig().GetUserAgent(); got != "test-agent" {
		t.Errorf("GlobalConfig().GetUserAgent() = %v, want %v", got, "test-agent")
	}
}

func TestClientsConfig(t *testing.T) {
	want := cpb.ClientsConfig_builder{}.Build()
	cfg := FromProto(cpb.Config_builder{Clients: want}.Build())

	if got := cfg.ClientsConfig(); !proto.Equal(got, want) {
		t.Errorf("ClientsConfig() = %v, want %v", got, want)
	}
}

func TestPluginsConfig(t *testing.T) {
	want := cpb.PluginsConfig_builder{}.Build()
	cfg := FromProto(cpb.Config_builder{Plugins: want}.Build())

	if got := cfg.PluginsConfig(); !proto.Equal(got, want) {
		t.Errorf("PluginsConfig() = %v, want %v", got, want)
	}
}
