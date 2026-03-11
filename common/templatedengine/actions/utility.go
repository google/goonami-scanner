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
	"context"
	"fmt"
	"time"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/log"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// UtilityActionRunner runs utility actions.
type UtilityActionRunner struct{}

// Run executes a utility action.
func (r *UtilityActionRunner) Run(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) error {
	utility := action.GetUtility()
	if utility == nil {
		return fmt.Errorf("%w: %q: not an utility action", ErrInvalidAction, action.GetName())
	}

	if sleep := utility.GetSleep(); sleep != nil {
		return sleepAction(ctx, sleep, env)
	}

	return fmt.Errorf("%w: %q: unsupported utility action", ErrInvalidAction, action.GetName())
}

func sleepAction(ctx context.Context, sleep *tpb.SleepUtilityAction, env *environment.Environment) error {
	disabled, ok := env.Get(environment.VarTestingDisableSleep)
	if ok && disabled == "true" {
		return nil
	}

	log.DebugContextf(ctx, log.DebugLevelRequest, "sleeping for %d ms", sleep.GetDurationMs())
	time.Sleep(time.Duration(sleep.GetDurationMs()) * time.Millisecond)
	return nil
}
