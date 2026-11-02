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
	"fmt"

	"github.com/google/goonami-scanner/common/bruteforce"
	"github.com/google/goonami-scanner/common/credentialstore"
	"github.com/google/goonami-scanner/common/templatedengine"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/module"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

//go:embed detections
var pluginFilesFS embed.FS

const (
	namePrefix = "dt/wktpl/"
)

func init() {
	sharedStore, err := credentialstore.NewWithDefaults()
	if err != nil {
		panic(fmt.Sprintf("failed to load default credentials: %v", err))
	}
	plugins, err := templatedengine.LoadPluginsFromFS(context.Background(), pluginFilesFS)
	if err != nil {
		panic(fmt.Sprintf("failed to load templated weak credential plugins: %v", err))
	}

	for _, pluginProto := range plugins {
		name := namePrefix + pluginProto.GetInfo().GetName()
		module.RegisterDetector(name, func(ctx context.Context, cfg *config.Config) (module.VulnDetector, error) {
			return NewFromProto(ctx, cfg, pluginProto, sharedStore)
		})
	}
}

// NewFromProto creates a new templated weak credentials detector backed by the generic brute-force library.
func NewFromProto(ctx context.Context, cfg *config.Config, pluginProto *tpb.TemplatedPlugin, store *credentialstore.CredentialStore) (module.VulnDetector, error) {
	baseDetector, err := templatedengine.New(ctx, cfg, pluginProto)
	if err != nil {
		return nil, err
	}

	return newDetector(ctx, cfg, pluginProto, baseDetector, store)
}

func newDetector(ctx context.Context, cfg *config.Config, pluginProto *tpb.TemplatedPlugin, baseDetector *templatedengine.TemplatedDetector, store *credentialstore.CredentialStore) (module.VulnDetector, error) {
	handler := &Handler{
		baseDetector: baseDetector,
		proto:        pluginProto,
	}

	opts := &bruteforce.Options{
		CredentialStore:    store,
		DefaultCredentials: defaultCredentials(pluginProto),
		PasswordOnly:       handler.isPasswordOnly(),
	}

	return bruteforce.New(ctx, cfg, handler, opts)
}

func defaultCredentials(pluginProto *tpb.TemplatedPlugin) []bruteforce.Credential {
	var creds []bruteforce.Credential
	for _, cred := range pluginProto.GetServiceInformation().GetDefaultCredentials() {
		creds = append(creds, bruteforce.Credential{
			Username: cred.GetLogin(),
			Password: cred.GetPassword(),
		})
	}
	return creds
}
