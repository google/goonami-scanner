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

package actions

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/log"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// HTTPActionRunner runs HTTP actions.
type HTTPActionRunner struct {
	client goohttp.Client
}

// NewHTTPActionRunner creates a new HTTPActionRunner.
func NewHTTPActionRunner(client goohttp.Client) *HTTPActionRunner {
	return &HTTPActionRunner{client: client}
}

// Run executes the HTTP action and return whether it was successful.
func (r *HTTPActionRunner) Run(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) bool {
	httpAction := action.GetHttpRequest()
	if httpAction == nil {
		log.ErrorContextf(ctx, "action '%s' is not an HTTP action", action.GetName())
		return false
	}

	for _, uri := range httpAction.GetUri() {
		if r.runWithURI(ctx, service, action, env, uri) {
			return true
		}
	}

	return false
}

func (r *HTTPActionRunner) runWithURI(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment, uri string) bool {
	uri = env.Substitute(ctx, uri)
	uri = strings.TrimPrefix(uri, "/")
	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		log.ErrorContextf(ctx, "failed to build web root: %v", err)
		return false
	}

	targetURL := webRoot + "/" + uri
	httpAction := action.GetHttpRequest()

	method := httpAction.GetMethod().String()
	if httpAction.GetMethod() == tpb.HttpAction_METHOD_UNSPECIFIED {
		log.ErrorContextf(ctx, "action '%s' has unspecified HTTP method", action.GetName())
		return false
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		log.ErrorContextf(ctx, "failed to create request: %v", err)
		return false
	}

	for _, header := range httpAction.GetHeaders() {
		req.Header.Add(header.GetName(), env.Substitute(ctx, header.GetValue()))
	}

	if data := httpAction.GetData(); data != "" {
		substitutedData := env.Substitute(ctx, data)
		req.Body = io.NopCloser(strings.NewReader(substitutedData))
		req.ContentLength = int64(len(substitutedData))
	}

	resp, err := goohttp.DefaultClient().Do(req)
	if err != nil {
		if !httpAction.GetClientOptions().GetIgnoreHttpClientErrors() {
			log.ErrorContextf(ctx, "HTTP request failed for action '%s': %v", action.GetName(), err)
		}
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.ErrorContextf(ctx, "failed to read response body: %v", err)
		return false
	}
	bodyString := string(bodyBytes)

	if expectedStatus := httpAction.GetResponse().GetHttpStatus(); expectedStatus != 0 {
		if int64(resp.StatusCode) != expectedStatus {
			log.DebugContextf(ctx, log.DebugLevelService, "workflow failed: expected status code %d, got %d", expectedStatus, resp.StatusCode)
			return false
		}
	}

	if !r.checkExpectations(ctx, resp, bodyString, httpAction, env) {
		return false
	}

	if !r.performExtractions(ctx, resp, bodyString, httpAction, env) {
		return false
	}

	return true
}

func (r *HTTPActionRunner) checkExpectations(ctx context.Context, resp *http.Response, body string, httpAction *tpb.HttpAction, env *environment.Environment) bool {
	response := httpAction.GetResponse()
	if expectAll := response.GetExpectAll(); expectAll != nil {
		for _, cond := range expectAll.GetConditions() {
			if !r.checkExpectation(ctx, resp, body, cond, env) {
				log.DebugContextf(ctx, log.DebugLevelService, "expectation failed: %v", cond)
				return false
			}
		}
		return true
	}

	if expectAny := response.GetExpectAny(); expectAny != nil {
		for _, cond := range expectAny.GetConditions() {
			if r.checkExpectation(ctx, resp, body, cond, env) {
				return true
			}
		}
		log.DebugContextf(ctx, log.DebugLevelService, "all expectations failed")
		return false
	}
	return true
}

func (r *HTTPActionRunner) checkExpectation(ctx context.Context, resp *http.Response, body string, cond *tpb.HttpAction_HttpResponse_Expectation, env *environment.Environment) bool {
	contains := env.Substitute(ctx, cond.GetContains())
	if cond.GetBody() != nil {
		return strings.Contains(body, contains)
	}
	if header := cond.GetHeader(); header != nil {
		headerName := env.Substitute(ctx, header.GetName())
		return strings.Contains(resp.Header.Get(headerName), contains)
	}
	return false
}

func (r *HTTPActionRunner) performExtractions(ctx context.Context, resp *http.Response, body string, httpAction *tpb.HttpAction, env *environment.Environment) bool {
	response := httpAction.GetResponse()
	if extractAll := response.GetExtractAll(); extractAll != nil {
		for _, ext := range extractAll.GetPatterns() {
			if !r.performExtraction(ctx, resp, body, ext, env) {
				log.DebugContextf(ctx, log.DebugLevelService, "extraction failed: %v", ext)
				return false
			}
		}
		return true
	}
	if extractAny := response.GetExtractAny(); extractAny != nil {
		for _, ext := range extractAny.GetPatterns() {
			if r.performExtraction(ctx, resp, body, ext, env) {
				return true
			}
		}
		log.DebugContextf(ctx, log.DebugLevelService, "all extractions failed")
		return false
	}
	return true
}

func (r *HTTPActionRunner) performExtraction(ctx context.Context, resp *http.Response, body string, ext *tpb.HttpAction_HttpResponse_Extract, env *environment.Environment) bool {
	varName := ext.GetVariableName()
	pattern := env.Substitute(ctx, ext.GetRegexp())

	if ext.GetFromBody() != nil {
		return env.Extract(ctx, body, varName, pattern)
	}
	if fromHeader := ext.GetFromHeader(); fromHeader != nil {
		headerName := env.Substitute(ctx, fromHeader.GetName())
		headerValue := resp.Header.Get(headerName)
		return env.Extract(ctx, headerValue, varName, pattern)
	}
	return false
}
