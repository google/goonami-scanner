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

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// CallbackServerActionRunner runs callback server actions.
type CallbackServerActionRunner struct {
	cfg *config.Config
}

// NewCallbackServerActionRunner creates a new CallbackServerActionRunner.
func NewCallbackServerActionRunner(cfg *config.Config) *CallbackServerActionRunner {
	return &CallbackServerActionRunner{cfg: cfg}
}

// Run executes a callback server action.
func (r *CallbackServerActionRunner) Run(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) error {
	name := action.GetName()
	client := callbackserver.DefaultClient()
	if !client.IsCallbackServerEnabled() {
		return fmt.Errorf("%w: %q: callback server is not enabled", ErrActionFailed, name)
	}

	if action.GetCallbackServer().GetActionType() != tpb.CallbackServerAction_CHECK {
		return fmt.Errorf("%w: %q: unknown action type %q", ErrInvalidAction, name, action.GetCallbackServer().GetActionType())
	}

	secret, ok := env.Get(environment.VarCallbackSecret)
	if !ok {
		return fmt.Errorf("%w: %q: callback secret not found in environment", ErrActionFailed, name)
	}

	hasInteraction, err := client.HasInteraction(ctx, secret)
	if err != nil {
		return fmt.Errorf("%w: %q: failed to check callback interaction: %v", ErrActionFailed, name, err)
	}

	if !hasInteraction {
		return fmt.Errorf("%w: %q: no callback interaction found", ErrActionFailed, name)
	}

	log.DebugContextf(ctx, log.DebugLevelService, "callback server interaction found")
	return nil
}
