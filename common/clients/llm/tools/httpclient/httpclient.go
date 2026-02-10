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
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"

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

	mut           sync.Mutex
	countRequests int
}

// Request is the request to be sent to the service.
type Request struct {
	Method  string            `json:"method" jsonschema:"Method to use: GET, POST."`
	URI     string            `json:"uri" jsonschema:"Absolute URI to request, for example '/' or '/index.html'."`
	Headers map[string]string `json:"headers" jsonschema:"Headers to be added to the request."`
	Data    string            `json:"data" jsonschema:"Data to send with the request"`
}

// Response is the response from an HTTP request.
type Response struct {
	StatusCode int32  `json:"status_code"`
	Content    string `json:"content"`
}

// DefaultConfig for the httpclient tool.
func DefaultConfig() *hccpb.HttpClientConfig {
	return hccpb.HttpClientConfig_builder{
		AllowedMethods:        []string{"GET", "POST"},
		MaxRequestsPerService: 50,
		MaxAnswerSizeBytes:    1 * 1024 * 1024, // 1 MB
		ForbiddenPaths: []string{
			".*abort.*", ".*delete.*", ".*drop.*", ".*huphuphup.*",
			".*kill.*", ".*quit.*", ".*remove.*",
		},
	}.Build()
}

// New returns a new instance of the httpclient tool.
func New(config *config.Config, service *nspb.NetworkService) (tool.Tool, error) {
	cfg := config.ClientsConfig().GetLlm()
	var toolcfg *hccpb.HttpClientConfig
	if !cfg.GetTools().HasHttpClientConfig() {
		toolcfg = DefaultConfig()
	} else {
		toolcfg = cfg.GetTools().GetHttpClientConfig()
	}

	var badPaths []*regexp.Regexp
	for _, path := range toolcfg.GetForbiddenPaths() {
		badPaths = append(badPaths, regexp.MustCompile(path))
	}

	t := &Tool{
		config:     toolcfg,
		coreConfig: config,
		service:    service,
		badPaths:   badPaths,
	}
	return functiontool.New(
		functiontool.Config{
			Name:        "httpclient",
			Description: "Performs an HTTP request against the service.",
		},
		t.Do,
	)
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

// Do performs an HTTP request against the service.
func (h *Tool) Do(toolctx tool.Context, toolreq *Request) (*Response, error) {
	port := h.service.GetNetworkEndpoint().GetPort().GetPortNumber()
	uri := toolreq.URI
	ctx, cancel := context.WithTimeout(context.Background(), h.coreConfig.TimeoutPerRequest())
	defer cancel()

	req, err := h.prepareRequest(ctx, toolreq, uri)
	if err != nil {
		return nil, err
	}

	h.increaseRequestCount()
	resp, err := goohttp.DefaultClient().Do(req)
	if err != nil {
		log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s %q error: %s", port, toolreq.Method, uri, err)
		return nil, err
	}
	defer resp.Body.Close()

	content, err := goohttp.ReadBody(resp, int(h.config.GetMaxAnswerSizeBytes()))
	if err != nil {
		log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s %q error: %s", port, toolreq.Method, uri, err)
		return nil, err
	}

	log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s %q status:%d content-length:%d req-data-length:%d", port, toolreq.Method, uri, resp.StatusCode, len(content), len(toolreq.Data))
	return &Response{
		StatusCode: int32(resp.StatusCode),
		Content:    string(content),
	}, nil
}

func (h *Tool) prepareRequest(ctx context.Context, toolreq *Request, path string) (*http.Request, error) {
	port := h.service.GetNetworkEndpoint().GetPort().GetPortNumber()
	uri := toolreq.URI

	if !strings.HasPrefix(uri, "/") || strings.Contains(uri, "://") || strings.Contains(uri, ":") {
		return nil, ErrInvalidURI
	}

	if !slices.Contains(h.config.GetAllowedMethods(), toolreq.Method) {
		log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s invalid method for %q", port, toolreq.Method, uri)
		return nil, ErrInvalidMethod
	}

	if h.numberOfRequests() >= int(h.config.GetMaxRequestsPerService()) {
		log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s too many requests for %q", port, toolreq.Method, uri)
		return nil, ErrTooManyRequests
	}

	for _, path := range h.badPaths {
		if path.MatchString(uri) {
			log.Debugf(log.DebugLevelRequest, "[clients/llm/httpclient] port:%d %s %q denied by regexp", port, toolreq.Method, uri)
			return nil, ErrContentDenied
		}
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

	for header, value := range toolreq.Headers {
		if header == "" {
			continue
		}

		req.Header.Set(header, value)
	}

	return req, nil
}
