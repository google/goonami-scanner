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

package module

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
)

// Registry coordinates the extensibility points of Goonami, including port scanners,
// fingerprinters, and detectors.
type Registry struct {
	mu             sync.RWMutex
	portScanners   map[string]InitPortScannerFn
	fingerprinters map[string]InitFingerprinterFn
	detectors      map[string]InitVulnDetectorFn

	portScannerNames   []string
	fingerprinterNames []string
	detectorNames      []string
}

// NewRegistry creates a new independent Registry instance.
func NewRegistry() *Registry {
	return &Registry{
		portScanners:   make(map[string]InitPortScannerFn),
		fingerprinters: make(map[string]InitFingerprinterFn),
		detectors:      make(map[string]InitVulnDetectorFn),
	}
}

// DefaultRegistry is the global registry used by default and self-registering packages.
var DefaultRegistry = NewRegistry()

// RegisterPortScanner registers a port scanner module.
func (r *Registry) RegisterPortScanner(name string, initFn InitPortScannerFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.portScanners[name]; exists {
		panic(fmt.Sprintf("module: RegisterPortScanner called twice for scanner %q", name))
	}
	r.portScannerNames = append(r.portScannerNames, name)
	r.portScanners[name] = initFn
}

// RegisterFingerprinter registers a fingerprinter module.
func (r *Registry) RegisterFingerprinter(name string, initFn InitFingerprinterFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.fingerprinters[name]; exists {
		panic(fmt.Sprintf("module: RegisterFingerprinter called twice for fingerprinter %q", name))
	}
	r.fingerprinterNames = append(r.fingerprinterNames, name)
	r.fingerprinters[name] = initFn
}

// RegisterDetector registers a vulnerability detector module.
func (r *Registry) RegisterDetector(name string, initFn InitVulnDetectorFn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.detectors[name]; exists {
		panic(fmt.Sprintf("module: RegisterDetector called twice for detector %q", name))
	}
	r.detectorNames = append(r.detectorNames, name)
	r.detectors[name] = initFn
}

// GetPortScanner initializes and returns the port scanner configured in WorkflowConfiguration.
func (r *Registry) GetPortScanner(ctx context.Context, cfg *config.Config) (PortScanner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	workflowCfg := cfg.WorkflowConfig()
	if workflowCfg.GetPortscan() == "" {
		return nil, fmt.Errorf("no port scanner specified in workflow configuration")
	}

	name := workflowCfg.GetPortscan()
	initFn, exists := r.portScanners[name]
	if !exists {
		return nil, fmt.Errorf("port scanner %q is not registered", name)
	}

	return initFn(ctx, cfg)
}

// GetFingerprinters initializes and returns the fingerprinters selected by the WorkflowConfiguration.
func (r *Registry) GetFingerprinters(ctx context.Context, cfg *config.Config) ([]Fingerprinter, error) {
	r.mu.RLock()
	// Copy names to ensure we preserve registration order deterministically
	names := make([]string, len(r.fingerprinterNames))
	copy(names, r.fingerprinterNames)

	registryMap := make(map[string]InitFingerprinterFn, len(r.fingerprinters))
	for k, v := range r.fingerprinters {
		registryMap[k] = v
	}
	r.mu.RUnlock()

	workflowCfg := cfg.WorkflowConfig()
	if workflowCfg.GetFingerprinters() == nil {
		return nil, nil
	}

	filter := workflowCfg.GetFingerprinters()
	resolved, err := resolveModules(ctx, "fingerprinters", names, filter.GetRequire(), filter.GetIgnore())
	if err != nil {
		return nil, err
	}

	var results []Fingerprinter
	for _, name := range resolved {
		initFn := registryMap[name]
		fp, err := initFn(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize fingerprinter %q: %w", name, err)
		}
		results = append(results, fp)
	}
	return results, nil
}

// GetDetectors initializes and returns the detectors selected by the WorkflowConfiguration.
func (r *Registry) GetDetectors(ctx context.Context, cfg *config.Config) ([]VulnDetector, error) {
	r.mu.RLock()
	// Copy names to ensure we preserve registration order deterministically
	names := make([]string, len(r.detectorNames))
	copy(names, r.detectorNames)

	registryMap := make(map[string]InitVulnDetectorFn, len(r.detectors))
	for k, v := range r.detectors {
		registryMap[k] = v
	}
	r.mu.RUnlock()

	workflowCfg := cfg.WorkflowConfig()
	if workflowCfg.GetDetectors() == nil {
		return nil, nil
	}

	filter := workflowCfg.GetDetectors()
	resolved, err := resolveModules(ctx, "detectors", names, filter.GetRequire(), filter.GetIgnore())
	if err != nil {
		return nil, err
	}

	var results []VulnDetector
	for _, name := range resolved {
		initFn := registryMap[name]
		dt, err := initFn(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize detector %q: %w", name, err)
		}
		results = append(results, dt)
	}
	return results, nil
}

// Clear clears all registered extensibility points.
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.portScanners = make(map[string]InitPortScannerFn)
	r.fingerprinters = make(map[string]InitFingerprinterFn)
	r.detectors = make(map[string]InitVulnDetectorFn)
	r.portScannerNames = nil
	r.fingerprinterNames = nil
	r.detectorNames = nil
}

// Package-level delegate functions supporting DefaultRegistry:

// RegisterPortScanner registers a port scanner module in the DefaultRegistry.
func RegisterPortScanner(name string, initFn InitPortScannerFn) {
	DefaultRegistry.RegisterPortScanner(name, initFn)
}

// RegisterFingerprinter registers a fingerprinter module in the DefaultRegistry.
func RegisterFingerprinter(name string, initFn InitFingerprinterFn) {
	DefaultRegistry.RegisterFingerprinter(name, initFn)
}

// RegisterDetector registers a vulnerability detector module in the DefaultRegistry.
func RegisterDetector(name string, initFn InitVulnDetectorFn) {
	DefaultRegistry.RegisterDetector(name, initFn)
}

// GetPortScanner initializes and returns the port scanner configured in DefaultRegistry.
func GetPortScanner(ctx context.Context, cfg *config.Config) (PortScanner, error) {
	return DefaultRegistry.GetPortScanner(ctx, cfg)
}

// GetFingerprinters initializes and returns the fingerprinters selected in DefaultRegistry.
func GetFingerprinters(ctx context.Context, cfg *config.Config) ([]Fingerprinter, error) {
	return DefaultRegistry.GetFingerprinters(ctx, cfg)
}

// GetDetectors initializes and returns the detectors selected in DefaultRegistry.
func GetDetectors(ctx context.Context, cfg *config.Config) ([]VulnDetector, error) {
	return DefaultRegistry.GetDetectors(ctx, cfg)
}

// ClearRegistry clears all registered modules in the DefaultRegistry.
func ClearRegistry() {
	DefaultRegistry.Clear()
}

// resolveModules performs the filtering and ordering of registered modules based on WorkflowConfiguration.
func resolveModules(
	ctx context.Context,
	category string,
	registeredNames []string,
	require []string,
	ignore []string,
) ([]string, error) {
	// Compile ignore regexes with full string anchors ^ and $
	var ignoreRes []*regexp.Regexp
	for _, pat := range ignore {
		re, err := regexp.Compile("^" + pat + "$")
		if err != nil {
			return nil, fmt.Errorf("invalid ignore pattern %q: %w", pat, err)
		}
		ignoreRes = append(ignoreRes, re)
	}

	// Compile require regexes with full string anchors ^ and $
	var requireRes []*regexp.Regexp
	for _, pat := range require {
		re, err := regexp.Compile("^" + pat + "$")
		if err != nil {
			return nil, fmt.Errorf("invalid require pattern %q: %w", pat, err)
		}
		requireRes = append(requireRes, re)
	}

	// For each require pattern, find matching registered modules.
	// We want to preserve the order of require patterns.
	// A module can only be added once.
	var selected []string
	selectedSet := make(map[string]bool)

	for i, re := range requireRes {
		pat := require[i]
		matchedAny := false
		for _, name := range registeredNames {
			if re.MatchString(name) {
				matchedAny = true
				if !selectedSet[name] {
					selectedSet[name] = true
					selected = append(selected, name)
				}
			}
		}
		if !matchedAny {
			return nil, fmt.Errorf("requested pattern %q for %s did not expand to any module", pat, category)
		}
	}

	// Now filter out ignored modules and log info
	var finalModules []string
	for _, name := range selected {
		ignored := false
		for _, re := range ignoreRes {
			if re.MatchString(name) {
				ignored = true
				break
			}
		}
		if ignored {
			log.InfoContextf(ctx, "module %q is ignored", name)
		} else {
			finalModules = append(finalModules, name)
		}
	}

	return finalModules, nil
}
