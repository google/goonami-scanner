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

// Package faketemplated provides a fake HTTP server and helpers for testing templated plugins.
package faketemplated

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"google.golang.org/protobuf/encoding/prototext"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	ttpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	npb "github.com/google/tsunami-security-scanner/proto/go/network_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// LoadPluginsAndTests walks the given filesystem and unmarshals all TemplatedPlugin and
// TemplatedPluginTests textprotos.
func LoadPluginsAndTests(fsys fs.FS) (map[string]*tpb.TemplatedPlugin, map[string]*ttpb.TemplatedPluginTests, error) {
	plugins := make(map[string]*tpb.TemplatedPlugin)
	tests := make(map[string]*ttpb.TemplatedPluginTests)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".textproto" {
			return nil
		}

		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil
		}

		if strings.HasSuffix(path, "_test.textproto") {
			test := &ttpb.TemplatedPluginTests{}
			if err := prototext.Unmarshal(content, test); err != nil {
				return err
			}

			tests[path] = test
			return nil
		}

		plugin := &tpb.TemplatedPlugin{}
		if err := prototext.Unmarshal(content, plugin); err != nil {
			return err
		}

		plugins[plugin.GetInfo().GetName()] = plugin
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return plugins, tests, nil
}

// NewHTTPServer creates a fake HTTP server driven by a TemplatedPluginTests_Test mock HTTP server
// specification and template environment.
func NewHTTPServer(ctx context.Context, mockServer *ttpb.MockHttpServer, env *environment.Environment) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responses := mockServer.GetMockResponses()

		for _, mockResp := range responses {
			mockURL := resolveMockURI(ctx, mockResp.GetUri(), env)
			if strings.HasPrefix(mockURL, environment.VarTestingMagicPrefix) {
				continue
			}
			if (r.URL.String() == mockURL || r.URL.Path == mockURL) && MatchesConditions(ctx, r, mockResp.GetCondition(), env) {
				writeMockResponse(ctx, w, mockResp, env, env.Substitute(ctx, mockResp.GetBodyContent()))
				return
			}
		}

		for _, mockResp := range responses {
			if env.Substitute(ctx, mockResp.GetUri()) == environment.VarTestingMagicAnyURI && MatchesConditions(ctx, r, mockResp.GetCondition(), env) {
				writeMockResponse(ctx, w, mockResp, env, env.Substitute(ctx, mockResp.GetBodyContent()))
				return
			}
		}

		for _, mockResp := range responses {
			if env.Substitute(ctx, mockResp.GetUri()) == environment.VarTestingMagicEchoServer && MatchesConditions(ctx, r, mockResp.GetCondition(), env) {
				writeMockResponse(ctx, w, mockResp, env, formatEchoBody(r))
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func resolveMockURI(ctx context.Context, rawURI string, env *environment.Environment) string {
	mockURL := env.Substitute(ctx, rawURI)
	// mockURL is the path, i.e. /index.php?foo=bar, so it should start with a "/". But if it is
	// one of the magic strings, it should not have a leading "/".
	if len(mockURL) > 0 && mockURL[0] != '/' && !strings.HasPrefix(mockURL, environment.VarTestingMagicPrefix) {
		return "/" + mockURL
	}
	return mockURL
}

func writeMockResponse(ctx context.Context, w http.ResponseWriter, mockResp *ttpb.MockHttpServer_MockResponse, env *environment.Environment, body string) {
	for _, header := range mockResp.GetHeaders() {
		w.Header().Add(header.GetName(), env.Substitute(ctx, header.GetValue()))
	}

	status := int(mockResp.GetStatus())
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func formatEchoBody(r *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
	for _, name := range slices.Sorted(maps.Keys(r.Header)) {
		for _, val := range r.Header[name] {
			fmt.Fprintf(&b, "%s: %s\n", name, val)
		}
	}
	b.WriteByte('\n')
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		b.Write(body)
	}
	return b.String()
}

// MatchesConditions reports whether an HTTP request satisfies all conditions in cond after
// substituting template variables from env.
func MatchesConditions(ctx context.Context, r *http.Request, cond *ttpb.MockHttpServer_HttpCondition, env *environment.Environment) bool {
	if cond == nil {
		return true
	}

	for _, header := range cond.GetHeaders() {
		if r.Header.Get(header.GetName()) != env.Substitute(ctx, header.GetValue()) {
			return false
		}
	}

	for _, param := range cond.GetGetParameter() {
		if r.URL.Query().Get(param.GetName()) != env.Substitute(ctx, param.GetValue()) {
			return false
		}
	}

	if cond.GetRequestType() != ttpb.MockHttpServer_UNKNOWN {
		if r.Method != cond.GetRequestType().String() {
			return false
		}
	}

	var bodyStr string
	if len(cond.GetBodyContent()) > 0 {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		bodyStr = string(body)
	}

	for _, content := range cond.GetBodyContent() {
		if !strings.Contains(bodyStr, env.Substitute(ctx, content)) {
			return false
		}
	}

	return true
}

// ServiceForServer builds a NetworkService proto pointing to the given httptest.Server.
func ServiceForServer(server *httptest.Server) (*nspb.NetworkService, error) {
	rawURL := strings.TrimPrefix(server.URL, "http://")
	hostPort := strings.Split(rawURL, ":")
	if len(hostPort) != 2 {
		return nil, fmt.Errorf("failed to parse host and port from URL of mock HTTP server: %s", rawURL)
	}

	host := hostPort[0]
	port := 80
	fmt.Sscanf(hostPort[1], "%d", &port)

	return nspb.NetworkService_builder{
		NetworkEndpoint: npb.NetworkEndpoint_builder{
			Type:     npb.NetworkEndpoint_IP_HOSTNAME_PORT,
			Hostname: npb.Hostname_builder{Name: host}.Build(),
			IpAddress: npb.IpAddress_builder{
				AddressFamily: npb.AddressFamily_IPV4,
				Address:       host,
			}.Build(),
			Port: npb.Port_builder{
				PortNumber: uint32(port),
			}.Build(),
		}.Build(),
		ServiceName:          "http",
		SupportedHttpMethods: []string{"GET", "POST", "PUT", "DELETE", "HEAD"},
	}.Build(), nil
}
