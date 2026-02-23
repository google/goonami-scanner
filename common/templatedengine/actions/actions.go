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

// Package actions provides implementations for the different actions used by the templated engine.
package actions

import (
	"context"

	"github.com/google/goonami-scanner/common/templatedengine/environment"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// ActionRunner is the interface for running a plugin action.
type ActionRunner interface {
	// Run executes the action and returns true if it succeeded.
	Run(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) bool
}
