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

package http

import (
	"net/url"
	"testing"
)

func TestIsURLPathForbidden(t *testing.T) {
	defaultForbidden := DefaultClientOptions().ForbiddenPaths

	tests := []struct {
		name      string
		targetURL string
		want      bool
	}{
		{
			name:      "when_kill_path_blocked",
			targetURL: "http://example.com/kill",
			want:      true,
		},
		{
			name:      "when_uppercase_kill_path_blocked",
			targetURL: "http://example.com/API/KILL",
			want:      true,
		},
		{
			name:      "when_percent_encoded_kill_path_blocked",
			targetURL: "http://example.com/%6b%69%6c%6c",
			want:      true,
		},
		{
			name:      "when_killall_path_blocked",
			targetURL: "http://example.com/killall",
			want:      true,
		},
		{
			name:      "when_underscore_kill_path_blocked",
			targetURL: "http://example.com/api/process_kill",
			want:      true,
		},
		{
			name:      "when_dot_dot_traversal_to_quit_blocked",
			targetURL: "http://example.com/safe/../quitquitquit",
			want:      true,
		},
		{
			name:      "when_abort_blocked",
			targetURL: "http://example.com/abort",
			want:      true,
		},
		{
			name:      "when_abortquitquit_blocked",
			targetURL: "http://example.com/abortquitquit",
			want:      true,
		},
		{
			name:      "when_huphuphup_blocked",
			targetURL: "http://example.com/huphuphup",
			want:      true,
		},
		{
			name:      "when_hyphenated_delete_user_blocked",
			targetURL: "http://example.com/api/delete-user",
			want:      true,
		},
		{
			name:      "when_drop_path_blocked",
			targetURL: "http://example.com/db/drop",
			want:      true,
		},
		{
			name:      "when_remove_path_blocked",
			targetURL: "http://example.com/api/remove",
			want:      true,
		},
		{
			name:      "when_query_param_contains_delete_blocked",
			targetURL: "http://example.com/admin?action=delete&id=1",
			want:      true,
		},
		{
			name:      "when_query_has_invalid_escape_still_evaluates_raw_query",
			targetURL: "http://example.com/admin?bad=%zz&action=delete",
			want:      true,
		},
		{
			name:      "when_hostname_contains_forbidden_word_but_path_is_benign_allowed",
			targetURL: "http://drop.kill.delete.example.com:8080/index.html",
			want:      false,
		},
		{
			name:      "when_skill_md_allowed",
			targetURL: "http://example.com/skill.md",
			want:      false,
		},
		{
			name:      "when_uppercase_skill_md_allowed",
			targetURL: "http://example.com/Skill.md",
			want:      false,
		},
		{
			name:      "when_dropdown_js_allowed",
			targetURL: "http://example.com/static/dropdown.js",
			want:      false,
		},
		{
			name:      "when_airdrop_js_allowed",
			targetURL: "http://example.com/static/airdrop.js",
			want:      false,
		},
		{
			name:      "when_backdrop_png_allowed",
			targetURL: "http://example.com/img/backdrop.png",
			want:      false,
		},
		{
			name:      "when_equity_overview_allowed",
			targetURL: "http://example.com/equity/overview",
			want:      false,
		},
		{
			name:      "when_ubiquitous_docs_allowed",
			targetURL: "http://example.com/docs/ubiquitous",
			want:      false,
		},
		{
			name:      "when_quitting_docs_allowed",
			targetURL: "http://example.com/docs/quitting",
			want:      false,
		},
		{
			name:      "when_killer_feature_allowed",
			targetURL: "http://example.com/blog/killer-feature",
			want:      false,
		},
		{
			name:      "when_all_caps_dropdown_js_allowed",
			targetURL: "http://example.com/STATIC/DROPDOWN.JS",
			want:      false,
		},
		{
			name:      "when_percent_encoded_skill_md_allowed",
			targetURL: "http://example.com/%73kill.md",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.targetURL)
			if err != nil {
				t.Fatalf("url.Parse(%q) failed: %v", tc.targetURL, err)
			}
			if got := IsURLPathForbidden(u, defaultForbidden); got != tc.want {
				t.Errorf("IsURLPathForbidden(%q) = %v, want %v", tc.targetURL, got, tc.want)
			}
		})
	}

	if IsURLPathForbidden(nil, defaultForbidden) {
		t.Errorf("IsURLPathForbidden(nil, defaultForbidden) = true, want false")
	}
}
