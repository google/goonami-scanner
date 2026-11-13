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
)

func TestSubstituteVariables(t *testing.T) {
	tests := []struct {
		name     string
		template string
		vars     map[string]string
		want     string
	}{
		{
			name:     "when_no_variables_in_template_returns_original",
			template: "/api/health",
			vars:     map[string]string{"foo": "bar"},
			want:     "/api/health",
		},
		{
			name:     "when_variable_matches_replaces_value",
			template: "/static/{{ bundle_file }}",
			vars:     map[string]string{"bundle_file": "main.1234.js"},
			want:     "/static/main.1234.js",
		},
		{
			name:     "when_variable_has_spaces_replaces_value",
			template: "/{{  app_path  }}/login",
			vars:     map[string]string{"app_path": "grafana"},
			want:     "/grafana/login",
		},
		{
			name:     "when_variable_not_in_map_keeps_placeholder",
			template: "/static/{{ missing }}",
			vars:     map[string]string{"other": "val"},
			want:     "/static/{{ missing }}",
		},
		{
			name:     "when_vars_is_empty_returns_template",
			template: "/{{ var }}",
			vars:     nil,
			want:     "/{{ var }}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SubstituteVariables(tc.template, tc.vars); got != tc.want {
				t.Errorf("SubstituteVariables(%q, %v) = %q, want %q", tc.template, tc.vars, got, tc.want)
			}
		})
	}
}
