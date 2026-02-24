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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
)

func TestRecordingHandler(t *testing.T) {
	validCBID, err := cbid.Generate("test")
	if err != nil {
		t.Fatalf("failed to generate CBID: %v", err)
	}
	cbidPath := fmt.Sprintf("/%s", validCBID)

	tests := []struct {
		name                 string
		path                 string
		expectedStatus       int
		expectedBody         string
		expectedInteractions int
	}{
		{
			name:                 "when_invalid_url_fails",
			path:                 "/invalid",
			expectedStatus:       http.StatusInternalServerError,
			expectedBody:         "",
			expectedInteractions: 0,
		},
		{
			name:                 "when_registration_succeeds_returns_ok",
			path:                 cbidPath,
			expectedStatus:       http.StatusOK,
			expectedBody:         `{"status":"OK"}`,
			expectedInteractions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Minute)
			handler := &RecordingHandler{Store: store}

			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("recording.ServeHTTP(): expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if diff := cmp.Diff(tt.expectedBody, rec.Body.String()); diff != "" {
				t.Errorf("recording.ServeHTTP(): unexpected body diff (-want +got):\n%s", diff)
			}

			gotInteractions := store.Get(validCBID)
			if len(gotInteractions) != tt.expectedInteractions {
				t.Errorf("recording.ServeHTTP(): expected %d interaction, got %d", tt.expectedInteractions, len(gotInteractions))
			}
		})
	}
}
