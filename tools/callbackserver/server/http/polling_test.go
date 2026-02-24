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

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	ppb "github.com/google/goonami-scanner/common/clients/callbackserver/polling_go_proto"
)

func TestPollingHandler(t *testing.T) {
	tests := []struct {
		name           string
		secret         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "when_no_secret_returns_bad_request",
			secret:         "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "required parameter 'secret' not found.\n",
		},
		{
			name:           "when_no_interaction_found_returns_not_found",
			secret:         "notfound",
			expectedStatus: http.StatusNotFound,
			expectedBody:   "interaction with secret not found\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Minute)
			handler := &PollingHandler{Store: store}

			req := httptest.NewRequest("GET", "/polling", nil)
			if tt.secret != "" {
				q := req.URL.Query()
				q.Add("secret", tt.secret)
				req.URL.RawQuery = q.Encode()
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if diff := cmp.Diff(tt.expectedBody, rec.Body.String()); diff != "" {
				t.Errorf("polling.ServeHTTP(): unexpected body diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPollingHandler_withInteractions(t *testing.T) {
	secret := "found"
	foundCBID, err := cbid.Generate("found")
	if err != nil {
		t.Fatalf("failed to generate CBID: %v", err)
	}

	tests := []struct {
		name           string
		interactions   []storage.Interaction
		expectedStatus int
		expectedJSON   string
	}{
		{
			name:           "when_both_HTTP_and_DNS_interactions_found_returns_json",
			expectedStatus: http.StatusOK,
			interactions: []storage.Interaction{
				{Type: storage.HTTPInteraction},
				{Type: storage.DNSInteraction},
			},
			expectedJSON: `{"hasDnsInteraction":true,"hasHttpInteraction":true}`,
		},
		{
			name:           "when_only_HTTP_interaction_found_returns_json",
			expectedStatus: http.StatusOK,
			interactions: []storage.Interaction{
				{Type: storage.HTTPInteraction},
			},
			expectedJSON: `{"hasHttpInteraction":true}`,
		},
		{
			name:           "when_only_DNS_interaction_found_returns_json",
			expectedStatus: http.StatusOK,
			interactions: []storage.Interaction{
				{Type: storage.DNSInteraction},
			},
			expectedJSON: `{"hasDnsInteraction":true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Minute)
			for _, interaction := range tt.interactions {
				if err := store.Register(foundCBID, interaction.Type); err != nil {
					t.Fatalf("failed to register interaction: %v", err)
				}
			}

			handler := &PollingHandler{Store: store}
			req := httptest.NewRequest("GET", "/polling", nil)
			q := req.URL.Query()
			q.Add("secret", secret)
			req.URL.RawQuery = q.Encode()

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			gotJSON := &ppb.PollingResult{}
			if err := protojson.Unmarshal(rec.Body.Bytes(), gotJSON); err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			wantJSON := &ppb.PollingResult{}
			if err := protojson.Unmarshal([]byte(tt.expectedJSON), wantJSON); err != nil {
				t.Fatalf("failed to unmarshal expected JSON: %v", err)
			}

			if diff := cmp.Diff(wantJSON, gotJSON, protocmp.Transform()); diff != "" {
				t.Errorf("polling.ServeHTTP(): unexpected JSON diff (-want +got):\n%s", diff)
			}
		})
	}
}
