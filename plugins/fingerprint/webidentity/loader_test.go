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

package webidentity

import (
	"testing"

	"google.golang.org/protobuf/proto"

	wfpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/webidentity_fp_config_go_proto"
)

func TestLoadAllFingerprints(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *wfpb.WebIdentityFpConfig
		wantMinFps int
	}{
		{
			name:       "when_loading_embedded_signatures_succeeds_with_catalog",
			cfg:        &wfpb.WebIdentityFpConfig{},
			wantMinFps: 30,
		},
		{
			name: "when_loading_from_signatures_directory_succeeds",
			cfg: wfpb.WebIdentityFpConfig_builder{
				SignaturesDirectory: proto.String("testdata/valid/"),
			}.Build(),
			wantMinFps: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fps, err := loadAllFingerprints(t.Context(), tc.cfg)
			if err != nil {
				t.Fatalf("loadAllFingerprints() returned unexpected error: %v", err)
			}
			if len(fps) < tc.wantMinFps {
				t.Errorf("len(loadAllFingerprints()) = %d, want >= %d", len(fps), tc.wantMinFps)
			}
		})
	}
}
