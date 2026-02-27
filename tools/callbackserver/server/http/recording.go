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

// Package http provides HTTP handlers for the callback server.
package http

import (
	"fmt"
	"net/http"

	"github.com/google/goonami-scanner/common/callbackserver/netutils"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
)

// RecordingHandler handles incoming HTTP requests to record interactions.
type RecordingHandler struct {
	Store storage.InteractionStore
}

func (h *RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// TODO: b/487253053 - Add support for HTTPS.
	fullURL := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
	cbid, err := netutils.IdentifierFromURL(fullURL)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelSession, "failed to extract CBID from URL '%s': %v", fullURL, err)
		w.WriteHeader(500)
		return
	}

	if err := h.Store.Register(cbid, storage.HTTPInteraction); err != nil {
		log.ErrorContextf(ctx, "failed to register HTTP interaction with CBID %q: %v", cbid, err)
		w.WriteHeader(500)
		return
	}

	log.DebugContextf(ctx, log.DebugLevelSession, "HTTP interaction with CBID %q recorded from IP %q", cbid, r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{\"status\":\"OK\"}"))
}
