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

// Package templatedengine provides the core logic for running templated detector plugins.
package templatedengine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

// TemplatedDetector is a vulnerability detector that runs templated plugins.
type TemplatedDetector struct {
	proto        *tpb.TemplatedPlugin
	knownActions map[string]*tpb.PluginAction
	httpClient   goohttp.Client

	// envForTesting forces the detector to use the specified shared environment. This is only used
	// for testing.
	envForTesting *environment.Environment
}

// New creates a new TemplatedDetector for a specific plugin.
func New(ctx context.Context, proto *tpb.TemplatedPlugin, httpClient goohttp.Client) (*TemplatedDetector, error) {
	actionsCache := make(map[string]*tpb.PluginAction)
	for _, action := range proto.GetActions() {
		actionsCache[action.GetName()] = action
	}

	return &TemplatedDetector{
		proto:        proto,
		knownActions: actionsCache,
		httpClient:   httpClient,
	}, nil
}

// NewForTesting creates a new TemplatedDetector for testing, forcing it to use the specified
// environment.
func NewForTesting(ctx context.Context, proto *tpb.TemplatedPlugin, httpClient goohttp.Client, env *environment.Environment) (*TemplatedDetector, error) {
	d, err := New(ctx, proto, httpClient)
	if err != nil {
		return nil, err
	}

	d.envForTesting = env
	return d, nil
}

// Name returns the name of the detector.
func (d *TemplatedDetector) Name() string {
	return fmt.Sprintf("dt/%s", d.proto.GetInfo().GetName())
}

// Detect performs the vulnerability detection.
func (d *TemplatedDetector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	for _, workflow := range d.proto.GetWorkflows() {
		if !d.workflowMeetsConditions(workflow) {
			continue
		}

		return d.runWorkflowForService(ctx, service, workflow)
	}

	log.WarnContextf(ctx, "current scanner configuration has no compatible workflow")
	return &dpb.DetectionReportList{}, nil
}

func (d *TemplatedDetector) workflowMeetsConditions(workflow *tpb.PluginWorkflow) bool {
	switch workflow.GetCondition() {
	case tpb.PluginWorkflow_REQUIRES_CALLBACK_SERVER:
		// TODO: b/483970797 - Check if callback server is enabled when implemented.
		return false
	default:
		return true
	}
}

func (d *TemplatedDetector) getRunnerForAction(action *tpb.PluginAction) actions.ActionRunner {
	if action.GetHttpRequest() != nil {
		return actions.NewHTTPActionRunner(d.httpClient)
	}
	if action.GetUtility() != nil {
		return &actions.UtilityActionRunner{}
	}
	if action.GetCallbackServer() != nil {
		return &actions.CallbackServerActionRunner{}
	}
	return nil
}

func (d *TemplatedDetector) dispatchAction(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) bool {
	if action.GetHttpRequest() != nil && !netservice.IsWebService(service) {
		return false
	}

	runner := d.getRunnerForAction(action)
	if runner == nil {
		log.ErrorContextf(ctx, "unsupported action type for action '%s'", action.GetName())
		return false
	}

	return runner.Run(ctx, service, action, env)
}

func (d *TemplatedDetector) runWorkflowForService(ctx context.Context, service *nspb.NetworkService, workflow *tpb.PluginWorkflow) (*dpb.DetectionReportList, error) {
	env := environment.New()
	env.InitializeFor(ctx, service)

	// Override for testing.
	if d.envForTesting != nil {
		env = d.envForTesting
	}

	for _, variable := range workflow.GetVariables() {
		val := env.Substitute(ctx, variable.GetValue())
		env.Set(variable.GetName(), val)
	}

	success := true
	var cleanupActions []string

	for _, actionName := range workflow.GetActions() {
		ok, cleanups := d.runActionFromName(ctx, service, actionName, env)
		if !ok {
			success = false
			break
		}

		cleanupActions = append(cleanupActions, cleanups...)
	}

	// Note that if cleanup fails but success was already true, we still want to report the
	// vulnerability while providing some feedback in the form of a log.
	for _, cleanupActionName := range cleanupActions {
		ok, _ := d.runActionFromName(ctx, service, cleanupActionName, env)
		if !ok {
			log.ErrorContextf(ctx, "cleanup action '%s' failed", cleanupActionName)
		}
	}

	if !success {
		return nil, nil
	}

	timestamp := &tspb.Timestamp{
		Seconds: time.Now().Unix(),
		Nanos:   int32(time.Now().Nanosecond()),
	}
	return dpb.DetectionReportList_builder{
		DetectionReports: []*dpb.DetectionReport{
			dpb.DetectionReport_builder{
				NetworkService:     service,
				DetectionTimestamp: timestamp,
				DetectionStatus:    dpb.DetectionStatus_VULNERABILITY_VERIFIED,
				Vulnerability:      d.proto.GetFinding(),
			}.Build(),
		},
	}.Build(), nil
}

// runActionFromName and return if it was successful but also the associated cleanup actions that must be
// run at the end of the workflow.
func (d *TemplatedDetector) runActionFromName(ctx context.Context, service *nspb.NetworkService, actionName string, env *environment.Environment) (bool, []string) {
	action, ok := d.knownActions[actionName]
	if !ok {
		log.ErrorContextf(ctx, "action '%s' not found in plugin '%s'", actionName, d.Name())
		return false, nil
	}

	return d.dispatchAction(ctx, service, action, env), action.GetCleanupActions()
}

// Registry is a helper to load all templated plugins.
type Registry struct {
	Detectors []module.InitVulnDetectorFn
}

// LoadPlugins loads all plugins from a given list of templated plugins.
func LoadPlugins(plugins []*tpb.TemplatedPlugin) []module.InitVulnDetectorFn {
	var seenPlugins []string
	var detectors []module.InitVulnDetectorFn
	for _, p := range plugins {
		pluginProto := p

		if slices.Contains(seenPlugins, pluginProto.GetInfo().GetName()) {
			continue
		}

		seenPlugins = append(seenPlugins, pluginProto.GetInfo().GetName())
		detectors = append(detectors, func(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
			return New(ctx, pluginProto, goohttp.DefaultClient())
		})
	}
	return detectors
}
