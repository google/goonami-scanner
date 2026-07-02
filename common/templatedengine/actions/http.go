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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/common/templatedengine/environment"
	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// HTTPActionRunner runs HTTP actions.
type HTTPActionRunner struct {
	cfg *config.Config
}

// NewHTTPActionRunner creates a new HTTPActionRunner.
func NewHTTPActionRunner(cfg *config.Config) *HTTPActionRunner {
	return &HTTPActionRunner{
		cfg: cfg,
	}
}

// Run executes the HTTP action and return whether it was successful.
func (r *HTTPActionRunner) Run(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment) error {
	httpAction := action.GetHttpRequest()
	if httpAction == nil {
		return fmt.Errorf("%w: %q: not an HTTP action", ErrInvalidAction, action.GetName())
	}

	if len(httpAction.GetUri()) == 0 {
		return fmt.Errorf("%w: %q: no URIs provided", ErrInvalidAction, action.GetName())
	}

	var resError error
	if len(httpAction.GetUri()) > 1 {
		resError = fmt.Errorf("all URIs failed detection")
	}

	for _, uri := range httpAction.GetUri() {
		err := r.runWithURI(ctx, service, action, env, uri)
		if err == nil {
			return nil
		}

		if !errors.Is(err, ErrActionFailed) {
			return err
		}

		if len(httpAction.GetUri()) > 1 {
			err = fmt.Errorf("  - %q: %w", uri, err)
		}

		resError = errors.Join(resError, err)
	}

	return resError
}

func (r *HTTPActionRunner) runWithURI(ctx context.Context, service *nspb.NetworkService, action *tpb.PluginAction, env *environment.Environment, uri string) error {
	name := action.GetName()
	uri = env.Substitute(ctx, uri)
	uri = strings.TrimPrefix(uri, "/")
	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return fmt.Errorf("%w: %q: failed to build web root: %v", ErrActionFailed, name, err)
	}

	targetURL := webRoot + "/" + uri
	httpAction := action.GetHttpRequest()

	method := httpAction.GetMethod().String()
	if httpAction.GetMethod() == tpb.HttpAction_METHOD_UNSPECIFIED {
		return fmt.Errorf("%w: %q: missing HTTP method", ErrInvalidAction, name)
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.TimeoutPerRequest())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %q: failed to create request: %v", ErrActionFailed, name, err)
	}

	for _, header := range httpAction.GetHeaders() {
		req.Header.Add(header.GetName(), env.Substitute(ctx, header.GetValue()))
	}

	if data := httpAction.GetData(); data != "" {
		substitutedData := env.Substitute(ctx, data)
		req.Body = io.NopCloser(strings.NewReader(substitutedData))
		req.ContentLength = int64(len(substitutedData))
	}

	client, err := r.getHTTPClient(r.cfg, httpAction)
	if err != nil {
		return fmt.Errorf("%w: %q: failed to create HTTP client: %v", ErrActionFailed, name, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		if !httpAction.GetClientOptions().GetIgnoreHttpClientErrors() {
			return fmt.Errorf("%w: %q: HTTP request failed: %v", ErrActionFailed, name, err)
		}

		// TODO: b/491438054 - This needs to be clarified. This behavior silently ignores all
		// expectations and extractions from the action.
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: %q: failed to read response body: %v", ErrActionFailed, name, err)
	}
	bodyString := string(bodyBytes)

	if expectedStatus := httpAction.GetResponse().GetHttpStatus(); expectedStatus != 0 {
		if int64(resp.StatusCode) != expectedStatus {
			return fmt.Errorf("%w: %q: response code mismatch: want %d, got %d", ErrActionFailed, name, expectedStatus, resp.StatusCode)
		}
	}

	if err := r.checkExpectations(ctx, resp, bodyString, name, httpAction, env); err != nil {
		return err
	}

	if err := r.performExtractions(ctx, resp, bodyString, name, httpAction, env); err != nil {
		return err
	}

	return nil
}

func (r *HTTPActionRunner) checkExpectations(ctx context.Context, resp *http.Response, body string, name string, httpAction *tpb.HttpAction, env *environment.Environment) error {
	response := httpAction.GetResponse()
	if expectAll := response.GetExpectAll(); expectAll != nil {
		for _, cond := range expectAll.GetConditions() {
			if err := r.checkExpectation(ctx, resp, body, name, cond, env); err != nil {
				return err
			}
		}
		return nil
	}

	if expectAny := response.GetExpectAny(); expectAny != nil {
		for _, cond := range expectAny.GetConditions() {
			err := r.checkExpectation(ctx, resp, body, name, cond, env)
			if err == nil {
				return nil
			}

			if !errors.Is(err, ErrActionFailed) {
				return err
			}
		}
		return fmt.Errorf("%w: %q: all expectations failed", ErrActionFailed, name)
	}

	return nil
}

func (r *HTTPActionRunner) checkExpectation(ctx context.Context, resp *http.Response, body string, name string, cond *tpb.HttpAction_HttpResponse_Expectation, env *environment.Environment) error {
	contains := env.Substitute(ctx, cond.GetContains())
	if cond.HasBody() {
		if strings.Contains(body, contains) {
			return nil
		}

		return fmt.Errorf("%w: %q: expectations: body does not contain %q", ErrActionFailed, name, contains)
	}

	if !cond.HasHeader() {
		return fmt.Errorf("%w: %q: invalid expectation %q", ErrInvalidAction, name, cond)
	}

	header := cond.GetHeader()
	headerName := env.Substitute(ctx, header.GetName())
	if strings.Contains(resp.Header.Get(headerName), contains) {
		return nil
	}

	return fmt.Errorf("%w: %q: expectations: header %q does not contain %q", ErrActionFailed, name, headerName, contains)
}

func (r *HTTPActionRunner) performExtractions(ctx context.Context, resp *http.Response, body string, name string, httpAction *tpb.HttpAction, env *environment.Environment) error {
	response := httpAction.GetResponse()
	if extractAll := response.GetExtractAll(); extractAll != nil {
		for _, ext := range extractAll.GetPatterns() {
			if err := r.performExtraction(ctx, resp, body, name, ext, env); err != nil {
				return err
			}
		}
		return nil
	}

	if extractAny := response.GetExtractAny(); extractAny != nil {
		for _, ext := range extractAny.GetPatterns() {
			err := r.performExtraction(ctx, resp, body, name, ext, env)
			if err == nil {
				return nil
			}

			if !errors.Is(err, ErrActionFailed) {
				return err
			}
		}
		return fmt.Errorf("%w: %q: all extractions failed", ErrActionFailed, name)
	}

	return nil
}

func (r *HTTPActionRunner) performExtraction(ctx context.Context, resp *http.Response, body string, name string, ext *tpb.HttpAction_HttpResponse_Extract, env *environment.Environment) error {
	varName := ext.GetVariableName()
	pattern := env.Substitute(ctx, ext.GetRegexp())

	if ext.HasFromBody() {
		if err := env.Extract(ctx, body, varName, pattern); err != nil {
			return fmt.Errorf("%w: %q: HTTP body: %v", ErrActionFailed, name, err)
		}

		return nil
	}

	if !ext.HasFromHeader() {
		return fmt.Errorf("%w: %q: invalid extraction %q", ErrInvalidAction, name, ext)
	}

	header := ext.GetFromHeader()
	headerName := env.Substitute(ctx, header.GetName())
	headerValue := resp.Header.Get(headerName)

	if err := env.Extract(ctx, headerValue, varName, pattern); err != nil {
		return fmt.Errorf("%w: %q: %q header: %v", ErrActionFailed, name, headerName, err)
	}

	return nil
}

func (r *HTTPActionRunner) getHTTPClient(cfg *config.Config, httpAction *tpb.HttpAction) (goohttp.Client, error) {
	if !httpAction.GetClientOptions().GetDisableFollowRedirects() {
		return goohttp.SharedClient(cfg), nil
	}

	opts := goohttp.DefaultClientOptions()
	opts.DisableFollowRedirects = true
	return goohttp.NewClient(cfg, opts)
}
