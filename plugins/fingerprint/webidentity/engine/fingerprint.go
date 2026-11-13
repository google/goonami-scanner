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

package engine

import (
	"errors"
	"fmt"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/matcher"
)

var (
	// ErrNilFingerprint is returned when attempting to compile a nil fingerprint.
	ErrNilFingerprint = errors.New("fingerprint cannot be nil")
	// ErrMissingSoftware is returned when fingerprint metadata lacks a software name.
	ErrMissingSoftware = errors.New("fingerprint missing software identifier in info")
	// ErrDuplicateStep is returned when two steps in the same fingerprint share the same name.
	ErrDuplicateStep = errors.New("duplicate step name in fingerprint")
)

// CompiledFingerprint contains pre-compiled steps, workflows, and metadata for a WebFingerprint.
type CompiledFingerprint struct {
	name      string
	software  string
	steps     map[string]*matcher.CompiledStep
	workflows []*matcher.CompiledWorkflow
	raw       *fpb.WebFingerprint
}

// Software returns the canonical software identifier.
func (cf *CompiledFingerprint) Software() string {
	return cf.software
}

// Name returns the descriptive plugin name.
func (cf *CompiledFingerprint) Name() string {
	return cf.name
}

// Raw returns the underlying raw WebFingerprint proto.
func (cf *CompiledFingerprint) Raw() *fpb.WebFingerprint {
	return cf.raw
}

// CompileFingerprint compiles a WebFingerprint protobuf into an executable fingerprint.
func CompileFingerprint(fp *fpb.WebFingerprint) (*CompiledFingerprint, error) {
	if fp == nil {
		return nil, ErrNilFingerprint
	}
	info := fp.GetInfo()
	if info.GetSoftware() == "" {
		return nil, ErrMissingSoftware
	}

	stepMap := make(map[string]*matcher.CompiledStep, len(fp.GetSteps()))
	for _, s := range fp.GetSteps() {
		cs, err := matcher.CompileStep(s)
		if err != nil {
			return nil, fmt.Errorf("fingerprint %q: %w", info.GetName(), err)
		}
		if _, exists := stepMap[cs.Name()]; exists {
			return nil, fmt.Errorf("fingerprint %q: %w %q", info.GetName(), ErrDuplicateStep, cs.Name())
		}
		stepMap[cs.Name()] = cs
	}

	workflows := make([]*matcher.CompiledWorkflow, 0, len(fp.GetWorkflows()))
	for i, w := range fp.GetWorkflows() {
		cw, err := matcher.CompileWorkflow(w, stepMap)
		if err != nil {
			return nil, fmt.Errorf("fingerprint %q workflow %d: %w", info.GetName(), i, err)
		}
		workflows = append(workflows, cw)
	}

	return &CompiledFingerprint{
		name:      info.GetName(),
		software:  info.GetSoftware(),
		steps:     stepMap,
		workflows: workflows,
		raw:       fp,
	}, nil
}
