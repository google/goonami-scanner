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

package actions

import (
	"testing"
	"time"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func TestUtilityActionRunner_Run(t *testing.T) {
	tests := []struct {
		name    string
		action  *tpb.PluginAction
		wantOk  bool
		minTime time.Duration
	}{
		{
			name: "when_sleep_action_sleeps",
			action: tpb.PluginAction_builder{
				Utility: tpb.UtilityAction_builder{
					Sleep: tpb.SleepUtilityAction_builder{DurationMs: 10}.Build(),
				}.Build(),
			}.Build(),
			wantOk:  true,
			minTime: 10 * time.Millisecond,
		},
		{
			name: "when_not_utility_action_returns_false",
			action: tpb.PluginAction_builder{
				HttpRequest: tpb.HttpAction_builder{}.Build(),
			}.Build(),
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &UtilityActionRunner{}
			env := environment.New(config.Default())
			start := time.Now()
			gotOk := runner.Run(t.Context(), nil, tc.action, env)
			elapsed := time.Since(start)

			if gotOk != tc.wantOk {
				t.Errorf("Run() = %v, want %v", gotOk, tc.wantOk)
			}
			if tc.minTime > 0 && elapsed < tc.minTime {
				t.Errorf("Run() took %v, want at least %v", elapsed, tc.minTime)
			}
		})
	}
}
