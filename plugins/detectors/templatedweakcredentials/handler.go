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

package templatedweakcredentials

import (
	"context"
	"errors"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/log"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

// Handler implements bruteforce.Handler for a templated weak credential plugin.
type Handler struct {
	baseDetector *templatedengine.TemplatedDetector
	proto        *tpb.TemplatedPlugin
}

// Name returns the unique module name of the detector.
func (h *Handler) Name() string {
	return namePrefix + h.proto.GetInfo().GetName()
}

// Fingerprint executes the ACTION_PHASE_FINGERPRINT phase of the templated workflow.
func (h *Handler) Fingerprint(ctx context.Context, service *nspb.NetworkService) (bool, error) {
	if _, err := h.baseDetector.DetectForPhase(ctx, service, tpb.PluginAction_ACTION_PHASE_FINGERPRINT, nil); err != nil {
		if errors.Is(err, actions.ErrActionFailed) {
			log.DebugContextf(ctx, log.DebugLevelService, "service fingerprinting failed: %v", err)
			return false, nil
		}

		if errors.Is(err, templatedengine.ErrNoCompatibleWorkflow) {
			log.WarnContextf(ctx, "no compatible workflow: %v", err)
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// NewWorker returns a Worker for testing credentials. Because Handler is
// stateless across attempts, it returns itself.
func (h *Handler) NewWorker() bruteforce.Worker {
	return h
}

// Close implements bruteforce.Worker.
func (h *Handler) Close() error {
	return nil
}

// TestCredential executes the ACTION_PHASE_DETECTION phase of the templated workflow
// with the candidate username and password injected into the template environment.
func (h *Handler) TestCredential(ctx context.Context, service *nspb.NetworkService, cred bruteforce.Credential) (bool, error) {
	extraVars := map[string]string{
		environment.VarWeakCredsPassword: cred.Password,
	}

	if !h.isPasswordOnly() {
		extraVars[environment.VarWeakCredsUsername] = cred.Username
	}

	reports, err := h.baseDetector.DetectForPhase(ctx, service, tpb.PluginAction_ACTION_PHASE_DETECTION, extraVars)
	if err != nil {
		if errors.Is(err, actions.ErrActionFailed) {
			log.DebugContextf(ctx, log.DebugLevelRequest, "attempt failed: %v", err)
			return false, nil
		}

		return false, err
	}

	return len(reports.GetDetectionReports()) > 0, nil
}

// Vulnerability returns the finding metadata defined by the templated plugin.
func (h *Handler) Vulnerability() *vpb.Vulnerability {
	return h.proto.GetFinding()
}

func (h *Handler) isPasswordOnly() bool {
	return h.proto.GetServiceInformation().GetAuthenticationType() == tpb.ServiceInformation_AUTHENTICATION_TYPE_PASSWORD_ONLY
}
