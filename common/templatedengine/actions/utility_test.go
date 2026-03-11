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
	"errors"
	"testing"
	"time"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func TestUtilityActionRunner_Run(t *testing.T) {
	tests := []struct {
		name         string
		action       *tpb.PluginAction
		wantErr      error
		minTime      time.Duration
		disableSleep bool
	}{
		{
			name: "when_sleep_action_sleeps",
			action: tpb.PluginAction_builder{
				Utility: tpb.UtilityAction_builder{
					Sleep: tpb.SleepUtilityAction_builder{DurationMs: 10}.Build(),
				}.Build(),
			}.Build(),
			minTime: 10 * time.Millisecond,
		},
		{
			name: "when_sleep_action_is_disabled_it_does_not_sleep",
			action: tpb.PluginAction_builder{
				Utility: tpb.UtilityAction_builder{
					Sleep: tpb.SleepUtilityAction_builder{DurationMs: 10000}.Build(),
				}.Build(),
			}.Build(),
			disableSleep: true,
		},
		{
			name: "when_not_utility_action_returns_error",
			action: tpb.PluginAction_builder{
				HttpRequest: tpb.HttpAction_builder{}.Build(),
			}.Build(),
			wantErr: ErrInvalidAction,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &UtilityActionRunner{}
			env := environment.New(config.Default())

			if tc.disableSleep {
				env.Set(environment.VarTestingDisableSleep, "true")
			}

			start := time.Now()
			err := runner.Run(t.Context(), nil, tc.action, env)
			elapsed := time.Since(start)

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Run() error = %v, wantErr %v", err, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			if tc.minTime > 0 && elapsed < tc.minTime {
				t.Errorf("Run() took %v, want at least %v", elapsed, tc.minTime)
			}
			if tc.disableSleep && elapsed >= 1*time.Second {
				t.Errorf("Run() took %v, but sleep should be disabled", elapsed)
			}
		})
	}
}
