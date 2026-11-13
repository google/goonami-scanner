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
	"testing"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"google.golang.org/protobuf/proto"
)

func TestCompileWorkflow(t *testing.T) {
	s1 := fpb.Step_builder{
		Name: "step1",
		Path: proto.String("/api/health"),
	}.Build()
	cs1, err := CompileStep(s1)
	if err != nil {
		t.Fatalf("CompileStep() unexpected error: %v", err)
	}
	stepMap := map[string]*CompiledStep{"step1": cs1}

	tests := []struct {
		name     string
		workflow *fpb.Workflow
		wantErr  bool
	}{
		{
			name:     "when_workflow_is_nil_returns_error",
			workflow: nil,
			wantErr:  true,
		},
		{
			name:     "when_workflow_has_no_steps_returns_error",
			workflow: &fpb.Workflow{},
			wantErr:  true,
		},
		{
			name: "when_workflow_references_unknown_step_returns_error",
			workflow: fpb.Workflow_builder{
				Steps: []string{"step1", "unknown_step"},
			}.Build(),
			wantErr: true,
		},
		{
			name: "when_workflow_is_valid_succeeds",
			workflow: fpb.Workflow_builder{
				Steps: []string{"step1"},
			}.Build(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cw, err := CompileWorkflow(tc.workflow, stepMap)
			if (err != nil) != tc.wantErr {
				t.Errorf("CompileWorkflow() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if err == nil {
				if len(cw.Steps()) != len(tc.workflow.GetSteps()) {
					t.Errorf("len(cw.Steps()) = %d, want %d", len(cw.Steps()), len(tc.workflow.GetSteps()))
				}
				if cw.Raw() != tc.workflow {
					t.Errorf("cw.Raw() = %v, want %v", cw.Raw(), tc.workflow)
				}
			}
		})
	}
}
