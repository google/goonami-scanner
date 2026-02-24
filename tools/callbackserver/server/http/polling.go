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

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/tools/callbackserver/storage"
	"google.golang.org/protobuf/encoding/protojson"

	ppb "github.com/google/goonami-scanner/common/clients/callbackserver/polling_go_proto"
)

// PollingHandler handles polling requests for interactions.
type PollingHandler struct {
	Store storage.InteractionStore
}

func (h *PollingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" {
		http.Error(w, "required parameter 'secret' not found.", http.StatusBadRequest)
		return
	}

	cbidStr, err := cbid.Generate(secret)
	if err != nil {
		log.ErrorContextf(r.Context(), "failed to generate CBID for secret '%s': %v", secret, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	interactions := h.Store.Get(cbidStr)

	if len(interactions) == 0 {
		log.DebugContextf(r.Context(), log.DebugLevelService, "interaction with secret '%s' NOT found and polled by IP %s", secret, r.RemoteAddr)
		http.Error(w, "interaction with secret not found", http.StatusNotFound)
		return
	}

	log.InfoContextf(r.Context(), "interaction with secret '%s' found and polled by IP %s", secret, r.RemoteAddr)
	result := ppb.PollingResult_builder{}

	for _, interaction := range interactions {
		switch interaction.Type {
		case storage.DNSInteraction:
			result.HasDnsInteraction = true
		case storage.HTTPInteraction:
			result.HasHttpInteraction = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp, err := protojson.Marshal(result.Build())
	if err != nil {
		log.ErrorContextf(r.Context(), "failed to marshal JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(resp)
}
