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

package log

import (
	"testing"
)

func TestColorize(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		color   string
		enabled bool
		want    string
	}{
		{
			name:    "when_enabled_it_applies_color",
			s:       "test",
			color:   ansiBoldRed,
			enabled: true,
			want:    ansiBoldRed + "test" + ansiReset,
		},
		{
			name:    "when_disabled_it_returns_original_string",
			s:       "test",
			color:   ansiBoldRed,
			enabled: false,
			want:    "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := colorize(tt.s, tt.color, tt.enabled); got != tt.want {
				t.Errorf("colorize() = %q, want %q", got, tt.want)
			}
		})
	}
}
