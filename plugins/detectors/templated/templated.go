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

	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"
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
	plugins, err := templatedengine.LoadPluginsFromFS(ctx, pluginFilesFS)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugins from FS: %w", err)
	}
	return templatedengine.LoadPlugins(l.cfg, plugins), nil
}
