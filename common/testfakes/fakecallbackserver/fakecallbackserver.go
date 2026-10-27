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

// Package fakecallbackserver provides a fake HTTP callback polling server for testing.
package fakecallbackserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	"google.golang.org/protobuf/proto"

	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
	cbpb "github.com/google/goonami-scanner/tools/callbackserver/callbackserver_config_go_proto"
)

// DefaultDNSDomain is the default DNS callback domain used in fake callback server configurations.
const DefaultDNSDomain = "cb.localhost.lan"

// Server is a fake implementation of the Goonami callback polling server.
type Server struct {
	server     *httptest.Server
	enabled    bool
	mu         sync.Mutex
	lastSecret string
}

// NewServer creates a new fake callback server configured with the given interaction state.
// When enabled is false or neither interaction flag is true, polling requests return HTTP 404.
func NewServer(enabled, hasHTTPInteraction, hasDNSInteraction bool) *Server {
	if !enabled || (!hasHTTPInteraction && !hasDNSInteraction) {
		return NewServerWithResponse(enabled, http.StatusNotFound, "not found")
	}
	body := fmt.Sprintf(`{"hasHttpInteraction": %t, "hasDnsInteraction": %t}`, hasHTTPInteraction, hasDNSInteraction)
	return NewServerWithResponse(enabled, http.StatusOK, body)
}

// NewServerWithResponse creates a new fake callback server that responds with the given HTTP status
// code and body on polling requests.
func NewServerWithResponse(enabled bool, status int, body string) *Server {
	s := &Server{
		enabled: enabled,
	}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.lastSecret = r.URL.Query().Get("secret")
		s.mu.Unlock()

		if !s.enabled {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	return s
}

// Close shuts down the fake callback server.
func (s *Server) Close() {
	s.server.Close()
}

// URL returns the base URL of the fake callback server.
func (s *Server) URL() string {
	return s.server.URL
}

// LastSecret returns the most recent "secret" query parameter received by the server.
func (s *Server) LastSecret() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSecret
}

// ClientConfig returns a CallbackserverConfig proto pointing to this fake server when enabled,
// or an empty config when disabled.
func (s *Server) ClientConfig() *cbpb.CallbackserverConfig {
	if !s.enabled {
		return cbpb.CallbackserverConfig_builder{}.Build()
	}
	return cbpb.CallbackserverConfig_builder{
		HttpPollConfig: cbpb.EndpointConfig_builder{
			PublicUri: proto.String(s.server.URL),
		}.Build(),
		HttpRecordConfig: cbpb.EndpointConfig_builder{
			PublicUri: proto.String(s.server.URL),
		}.Build(),
		DnsRecordConfig: cbpb.EndpointConfig_builder{
			PublicUri: proto.String(DefaultDNSDomain),
		}.Build(),
	}.Build()
}

// ClientsConfig returns a ClientsConfig proto containing this server's CallbackserverConfig.
func (s *Server) ClientsConfig() *cpb.ClientsConfig {
	return cpb.ClientsConfig_builder{
		CallbackServer: s.ClientConfig(),
	}.Build()
}
