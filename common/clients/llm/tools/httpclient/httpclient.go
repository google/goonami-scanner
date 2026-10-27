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

// Package httpclient provide an LLM tool to perform HTTP requests in the context of Goonami.
package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/protobuf/proto"

	hccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var (
	// ErrContentDenied is returned when we deny access to a specific resource to the agent.
	ErrContentDenied = errors.New("content access denied by the tool")

	// ErrInvalidURI is returned when the agent tries to request a URI that is not valid.
	ErrInvalidURI = errors.New("invalid URI, absolute URI starting with '/' expected")

	// ErrInvalidMethod is returned when the agent tries to use an HTTP method that is not supported.
	ErrInvalidMethod = errors.New("invalid HTTP method, expected GET or POST")

	// ErrTooManyRequests is returned when the agent tries to make too many requests to the
	// same service.
	ErrTooManyRequests = errors.New("max requests limit reached: please stop using the tool")
)

// Tool is specific to each Goonami network service and ensures that the agent can only perform
// HTTP requests in the context of the service.
type Tool struct {
	config     *hccpb.HttpClientConfig
	coreConfig *config.Config
	service    *nspb.NetworkService
	badPaths   []*regexp.Regexp

	mut             sync.Mutex
	client          goohttp.Client
	statelessClient goohttp.Client
	countRequests   int
}

// Header represents a key-value header pair.
type Header struct {
	Name  string `json:"name" jsonschema:"Header name, e.g. 'Content-Type'."`
	Value string `json:"value" jsonschema:"Header value, e.g. 'application/json'."`
}

// Request is the request to be sent to the service.
type Request struct {
	Method          string   `json:"method" jsonschema:"Method to use: GET, POST."`
	URI             string   `json:"uri" jsonschema:"Absolute URI to request, for example '/' or '/index.html'."`
	Headers         []Header `json:"headers" jsonschema:"Optional HTTP headers list. Only include required headers such as 'Content-Type'."`
	Data            string   `json:"data" jsonschema:"Data to send with the request"`
	MaintainSession bool     `json:"maintain_session" jsonschema:"If true, cookies from the response will be saved and sent on subsequent requests where this flag is also true."`
	ClearSession    bool     `json:"clear_session" jsonschema:"If true, wipes the existing cookie jar before executing the request."`
}

// Response is the response from an HTTP request.
type Response struct {
	StatusCode int32             `json:"status_code" jsonschema:"HTTP status code returned by the server."`
	FinalURI   string            `json:"final_uri" jsonschema:"Final request URI after following any in-scope redirects (e.g. '/login')."`
	Headers    map[string]string `json:"headers" jsonschema:"High-signal HTTP response headers (e.g. Content-Type, Location, Refresh, Server, Set-Cookie, Www-Authenticate)."`
	Content    string            `json:"content" jsonschema:"Raw body content returned by the server."`
}

// DefaultConfig for the httpclient tool.
func DefaultConfig() *hccpb.HttpClientConfig {
	return hccpb.HttpClientConfig_builder{
		AllowedMethods: []string{"GET", "POST"},
		ForbiddenPaths: goohttp.DefaultForbiddenPathPatterns(),
	}.Build()
}

// New returns a new instance of the httpclient tool as a tool.Tool from the ADK.
func New(config *config.Config, service *nspb.NetworkService) (tool.Tool, error) {
	t, err := newTool(config, service)
	if err != nil {
		return nil, err
	}
	return functiontool.New(
		functiontool.Config{
			Name:        "httpclient",
			Description: "Performs an HTTP request against the service.",
		},
		t.Do,
	)
}

func newTool(config *config.Config, service *nspb.NetworkService) (*Tool, error) {
	cfg := DefaultConfig()
	if config.ClientsConfig().GetLlm().GetTools().HasHttpClientConfig() {
		userCfg := config.ClientsConfig().GetLlm().GetTools().GetHttpClientConfig()
		if len(userCfg.GetAllowedMethods()) > 0 {
			cfg.SetAllowedMethods(nil)
		}
		if len(userCfg.GetForbiddenPaths()) > 0 {
			cfg.SetForbiddenPaths(nil)
		}
		proto.Merge(cfg, userCfg)
	}

	var badPaths []*regexp.Regexp
	for _, pattern := range cfg.GetForbiddenPaths() {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		badPaths = append(badPaths, re)
	}

	statelessOpts := &goohttp.ClientOptions{
		StoreCookies:   false,
		ForbiddenPaths: badPaths,
	}
	if err := statelessOpts.LoadAuthorities(service); err != nil {
		return nil, err
	}

	statelessClient, err := goohttp.NewClient(config, statelessOpts)
	if err != nil {
		return nil, err
	}

	t := &Tool{
		config:          cfg,
		coreConfig:      config,
		service:         service,
		badPaths:        badPaths,
		statelessClient: statelessClient,
	}
	if err := t.clearSession(); err != nil {
		return nil, err
	}
	return t, nil
}

func (h *Tool) increaseRequestCount() {
	h.mut.Lock()
	defer h.mut.Unlock()
	h.countRequests++
}

func (h *Tool) numberOfRequests() int {
	h.mut.Lock()
	defer h.mut.Unlock()
	return h.countRequests
}

func (h *Tool) clearSession() error {
	opts := &goohttp.ClientOptions{
		StoreCookies:   true,
		ForbiddenPaths: h.badPaths,
	}
	if err := opts.LoadAuthorities(h.service); err != nil {
		return err
	}

	client, err := goohttp.NewClient(h.coreConfig, opts)
	if err != nil {
		return err
	}
	h.mut.Lock()
	h.client = client
	h.mut.Unlock()
	return nil
}

func (h *Tool) getClient(maintainSession bool) goohttp.Client {
	if maintainSession {
		h.mut.Lock()
		defer h.mut.Unlock()
		return h.client
	}

	return h.statelessClient
}

// Do performs an HTTP request against the service.
func (h *Tool) Do(toolctx agent.Context, toolreq *Request) (*Response, error) {
	var baseCtx context.Context = toolctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	if err := baseCtx.Err(); err != nil {
		return nil, err
	}

	uri := toolreq.URI
	ctx := log.ContextForModuleAndService(baseCtx, "clients/llm/httpclient", h.service)

	req, err := h.prepareRequest(ctx, toolreq)
	if err != nil {
		return nil, err
	}

	h.increaseRequestCount()

	if toolreq.ClearSession {
		if err := h.clearSession(); err != nil {
			return nil, err
		}
	}

	client := h.getClient(toolreq.MaintainSession)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	content, err := goohttp.ReadBody(resp, int(h.config.GetMaxAnswerSizeBytes()))
	if err != nil {
		return nil, err
	}

	finalURI := uri
	if resp.Request != nil && resp.Request.URL != nil {
		finalURI = resp.Request.URL.RequestURI()
	}

	return &Response{
		StatusCode: int32(resp.StatusCode),
		FinalURI:   finalURI,
		Headers:    extractRelevantHeaders(resp),
		Content:    string(content),
	}, nil
}

func (h *Tool) prepareRequest(ctx context.Context, toolreq *Request) (*http.Request, error) {
	uri := toolreq.URI

	if !strings.HasPrefix(uri, "/") || strings.Contains(uri, "://") || strings.Contains(uri, ":") {
		return nil, ErrInvalidURI
	}

	if !slices.Contains(h.config.GetAllowedMethods(), toolreq.Method) {
		log.DebugContextf(ctx, log.DebugLevelRequest, "invalid method for %q: %q", toolreq.Method, uri)
		return nil, ErrInvalidMethod
	}

	if h.numberOfRequests() >= int(h.config.GetMaxRequestsPerService()) {
		metrics.BudgetExhausted.Add(ctx, 1,
			metrics.Module("clients/llm/httpclient"),
			metrics.LimitName(metrics.LimitMaxRequestsPerService))
		log.DebugContextf(ctx, log.DebugLevelRequest, "too many requests for %q: %q", toolreq.Method, uri)
		return nil, ErrTooManyRequests
	}

	webroot, err := netservice.BuildWebRoot(h.service)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if toolreq.Data != "" {
		body = strings.NewReader(toolreq.Data)
	}

	url := webroot + uri
	req, err := http.NewRequestWithContext(ctx, toolreq.Method, url, body)
	if err != nil {
		return nil, err
	}

	if goohttp.IsURLPathForbidden(req.URL, h.badPaths) {
		log.DebugContextf(ctx, log.DebugLevelRequest, "%q denied by regexp: %q", toolreq.Method, uri)
		return nil, ErrContentDenied
	}

	for _, header := range toolreq.Headers {
		if header.Name == "" {
			continue
		}

		req.Header.Set(header.Name, header.Value)
	}

	return req, nil
}

var relevantResponseHeaders = []string{
	"Content-Type",
	"Location",
	"Refresh",
	"Server",
	"Set-Cookie",
	"Www-Authenticate",
}

// extractRelevantHeaders filters and returns high-signal HTTP response headers from the final
// response and preserves any Set-Cookie headers issued across intermediate in-scope redirect hops
// in chronological order. Keys in http.Response.Header are guaranteed to be canonicalized by
// net/http, enabling direct O(1) lookups without scanning or lowercasing all response headers.
func extractRelevantHeaders(resp *http.Response) map[string]string {
	extracted := make(map[string]string)
	if resp == nil {
		return extracted
	}
	for _, key := range relevantResponseHeaders {
		if vals := resp.Header[key]; len(vals) > 0 {
			extracted[key] = strings.Join(vals, ", ")
		}
	}

	var chain []*http.Response
	for cur := resp; cur != nil; {
		chain = append(chain, cur)
		if cur.Request == nil {
			break
		}
		cur = cur.Request.Response
	}
	if len(chain) <= 1 {
		return extracted
	}

	// Reverse so redirect hops are processed in chronological order (initial hop to final response).
	slices.Reverse(chain)
	var cookies []string
	for _, hop := range chain {
		cookies = append(cookies, hop.Header["Set-Cookie"]...)
	}
	if len(cookies) > 0 {
		extracted["Set-Cookie"] = strings.Join(cookies, ", ")
	}
	return extracted
}
