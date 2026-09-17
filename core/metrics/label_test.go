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

package metrics

import (
	"strings"
	"testing"
)

func TestSanitizeValue(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "when_the_value_is_clean_it_is_unchanged",
			value: "webidentity",
			want:  "webidentity",
		},
		{
			name:  "when_the_value_has_surrounding_spaces_they_are_trimmed",
			value: "  webidentity  ",
			want:  "webidentity",
		},
		{
			name:  "when_the_value_is_empty_it_becomes_unknown",
			value: "",
			want:  "unknown",
		},
		{
			name:  "when_the_value_is_only_spaces_it_becomes_unknown",
			value: "   ",
			want:  "unknown",
		},
		{
			name:  "when_the_value_contains_control_characters_they_are_replaced",
			value: "web\nidentity\t",
			want:  "web_identity",
		},
		{
			name:  "when_the_value_is_too_long_it_is_truncated",
			value: strings.Repeat("a", maxLabelValueLength+10),
			want:  strings.Repeat("a", maxLabelValueLength),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeValue(tc.value); got != tc.want {
				t.Errorf("sanitizeValue(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
