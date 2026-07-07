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

// Package templatedweakcredentials provides a loader for templated weak credential detector plugins.
package templatedweakcredentials

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/common/templatedengine/actions"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/module"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
	vpb "github.com/google/tsunami-security-scanner/proto/go/vulnerability_go_proto"
)

//go:embed detections
var pluginFilesFS embed.FS

func init() {
	sharedStore := NewCredentialStore()
	plugins, err := templatedengine.LoadPluginsFromFS(context.Background(), pluginFilesFS)
	if err != nil {
		panic(fmt.Sprintf("failed to load templated weak credential plugins: %v", err))
	}

	for _, proto := range plugins {
		name := proto.GetInfo().GetName()
		module.RegisterDetector(name, func(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
			return NewFromProto(ctx, cfg, proto, sharedStore)
		})
	}
}

// NewFromProto creates a new templated weak credentials detector.
func NewFromProto(ctx context.Context, cfg *config.Config, pluginProto *tpb.TemplatedPlugin, store *CredentialStore) (module.VulnDetector, error) {
	baseDetector, err := templatedengine.New(ctx, cfg, pluginProto)
	if err != nil {
		return nil, err
	}

	// We perform the load on the shared store before copying it to avoid loading the files multiple
	// times.
	if err := store.LoadFromConfigOnce(ctx, cfg); err != nil {
		return nil, err
	}

	d := &Detector{
		cfg:          cfg,
		baseDetector: baseDetector,
		proto:        pluginProto,
		store:        store.Copy(),
	}

	d.loadCredentials(ctx)
	return d, nil
}

// Detector is a detector that brute forces specific credentials.
type Detector struct {
	cfg          *config.Config
	baseDetector *templatedengine.TemplatedDetector
	proto        *tpb.TemplatedPlugin
	store        *CredentialStore
}

// Name returns the name of the detector.
func (d *Detector) Name() string {
	return fmt.Sprintf("dt/wktpl/%s", d.proto.GetInfo().GetName())
}

func (d *Detector) loadCredentials(ctx context.Context) {
	// Important note: order in which credentials are added matters. The credentialstore keeps the
	// username and passwords in the order they are added. All passwords of a given username are
	// tested in that order. When loading credentials, we want to ensure the ones specific to the
	// service (default or common credentials) are tried first, hence why they are prepended.
	log.DebugContextf(ctx, log.DebugLevelSession, "loading default credentials from templated plugin configuration")
	defaults := d.proto.GetServiceInformation().GetDefaultCredentials()
	for _, cred := range defaults {
		user := cred.GetLogin()
		pass := cred.GetPassword()

		if d.proto.GetServiceInformation().GetAuthenticationType() == tpb.ServiceInformation_AUTHENTICATION_TYPE_PASSWORD_ONLY {
			user = ""
		}

		if err := d.store.PrependUser(user); err != nil {
			log.WarnContextf(ctx, "failed to prepend user: %v", err)
		}
		if err := d.store.PrependPasswordForUser(user, pass); err != nil {
			log.WarnContextf(ctx, "failed to prepend password: %v", err)
		}
	}
}

// Detect loops over registered credentials and issues detect workflows.
func (d *Detector) Detect(ctx context.Context, service *nspb.NetworkService) (*dpb.DetectionReportList, error) {
	maxAttempts := d.cfg.PluginsConfig().GetTemplatedweakcredentials().GetMaxAttemptsPerService()
	log.DebugContextf(ctx, log.DebugLevelService, "%d credentials generated (max attempts: %d) and will be used against the service", d.store.Count(), maxAttempts)

	var attempts int32

	for _, username := range d.store.Usernames() {
		for _, password := range d.store.Passwords(username) {
			if maxAttempts > 0 && attempts >= maxAttempts {
				log.DebugContextf(ctx, log.DebugLevelService, "reached maximum authentication attempts limit of %d", maxAttempts)
				return nil, nil
			}
			attempts++

			extraVars := map[string]string{
				"T_PASSWORD": password,
			}

			if d.proto.GetServiceInformation().GetAuthenticationType() != tpb.ServiceInformation_AUTHENTICATION_TYPE_PASSWORD_ONLY {
				extraVars["T_USERNAME"] = username
			}

			log.DebugContextf(ctx, log.DebugLevelRequest, "attempting detection with credentials %s:%s", username, password)
			reports, err := d.baseDetector.DetectWithVariables(ctx, service, extraVars)
			if err != nil {
				if errors.Is(err, actions.ErrActionFailed) {
					log.DebugContextf(ctx, log.DebugLevelRequest, "attempt failed: %v", err)
					continue
				}

				if errors.Is(err, templatedengine.ErrNoCompatibleWorkflow) {
					log.WarnContextf(ctx, "no compatible workflow found for service")
					return nil, nil
				}

				return nil, err
			}

			// No valid credentials identified.
			if reports == nil || len(reports.GetDetectionReports()) == 0 {
				continue
			}

			additionalDetails := vpb.AdditionalDetail_builder{
				TextData: vpb.TextData_builder{
					Text: fmt.Sprintf("%s:%s", username, password),
				}.Build(),
			}.Build()

			for _, report := range reports.GetDetectionReports() {
				if report.GetVulnerability() == nil {
					continue
				}

				vuln := report.GetVulnerability()
				details := vuln.GetAdditionalDetails()
				details = append(details, additionalDetails)
				vuln.SetAdditionalDetails(details)
				report.SetVulnerability(vuln)
			}

			log.DebugContextf(ctx, log.DebugLevelService, "valid credentials identified after %d attempt(s): %s:%s", attempts, username, password)
			return reports, nil
		}
	}

	log.DebugContextf(ctx, log.DebugLevelService, "no valid credentials found after %d attempt(s)", attempts)
	return nil, nil
}
