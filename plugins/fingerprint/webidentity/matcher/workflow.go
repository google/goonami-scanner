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

package matcher

import (
	"errors"
	"fmt"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

var (
	// ErrNilWorkflow is returned when compiling a nil Workflow.
	ErrNilWorkflow = errors.New("workflow cannot be nil")
	// ErrEmptyWorkflow is returned when compiling a Workflow with no steps.
	ErrEmptyWorkflow = errors.New("workflow must contain at least one step")
	// ErrUnknownStep is returned when a Workflow references a step name not present in the step map.
	ErrUnknownStep = errors.New("workflow references unknown step")
)

// CompiledWorkflow contains a pre-compiled sequence of steps referenced by a workflow.
type CompiledWorkflow struct {
	steps []*CompiledStep
	raw   *fpb.Workflow
}

// Steps returns the compiled steps belonging to this workflow.
func (cw *CompiledWorkflow) Steps() []*CompiledStep {
	return cw.steps
}

// Raw returns the underlying protobuf workflow.
func (cw *CompiledWorkflow) Raw() *fpb.Workflow {
	return cw.raw
}

// CompileWorkflow resolves and compiles a protobuf Workflow against a map of compiled steps.
func CompileWorkflow(w *fpb.Workflow, stepMap map[string]*CompiledStep) (*CompiledWorkflow, error) {
	if w == nil {
		return nil, ErrNilWorkflow
	}
	if len(w.GetSteps()) == 0 {
		return nil, ErrEmptyWorkflow
	}

	steps := make([]*CompiledStep, 0, len(w.GetSteps()))
	for _, stepName := range w.GetSteps() {
		cs, ok := stepMap[stepName]
		if !ok || cs == nil {
			return nil, fmt.Errorf("%w: %q", ErrUnknownStep, stepName)
		}
		steps = append(steps, cs)
	}

	return &CompiledWorkflow{
		steps: steps,
		raw:   w,
	}, nil
}
