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

// Package templated provides a loader for templated detector plugins.
package templated

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	"google.golang.org/protobuf/encoding/prototext"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

//go:embed detections
var pluginFilesFS embed.FS

// Loader loads templated detectors.
type Loader struct {
	cfg *config.Config
}

// NewLoader creates a new Loader.
func NewLoader(cfg *config.Config) *Loader {
	return &Loader{cfg: cfg}
}

// AllPlugins loads all templated detectors found in the embedded directory.
func (l *Loader) AllPlugins(ctx context.Context) ([]module.InitVulnDetectorFn, error) {
	var plugins []*tpb.TemplatedPlugin

	err := fs.WalkDir(pluginFilesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if d.IsDir() || filepath.Ext(path) != ".textproto" || strings.HasSuffix(path, "_test.textproto") {
			return nil
		}

		plugin, err := loadPlugin(ctx, path)
		if err != nil || plugin == nil {
			return err
		}

		plugins = append(plugins, plugin)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk embedded plugins: %w", err)
	}

	return templatedengine.LoadPlugins(l.cfg, plugins), nil
}

func loadPlugin(ctx context.Context, path string) (*tpb.TemplatedPlugin, error) {
	content, err := pluginFilesFS.ReadFile(path)
	if err != nil {
		log.WarnContextf(ctx, "failed to read plugin file %s: %v", path, err)
		return nil, err
	}

	plugin := &tpb.TemplatedPlugin{}
	if err := prototext.Unmarshal(content, plugin); err != nil {
		log.WarnContextf(ctx, "failed to unmarshal plugin %s: %v", path, err)
		return nil, err
	}

	if plugin.GetConfig().GetDisabled() {
		log.InfoContextf(ctx, "plugin %s is disabled, skipping", path)
		return nil, nil
	}

	return plugin, nil
}
