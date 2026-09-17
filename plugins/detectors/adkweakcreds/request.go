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

package adkweakcreds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/goonami-scanner/core/config"
	goohttp "github.com/google/goonami-scanner/core/net/http"
	"github.com/google/goonami-scanner/core/net/netservice"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var (
	errInvalidURL        = errors.New("request of strategy contains an invalid URL")
	errNoExtractionRegex = errors.New("request of strategy has an empty extraction_regex")
)

// request defines how to create an HTTP request.
type request struct {
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	Body            string    `json:"body"`
	ExtractionRegex string    `json:"extraction_regex"`
	Headers         []*header `json:"headers"`

	rex *regexp.Regexp
}

// String returns the JSON representation of the request, or a fallback string if marshaling fails.
func (r *request) String() string {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf("request(method=%s, path=%s)", r.Method, r.Path)
	}
	return string(b)
}

// compileAndValidate validates the request and compiles the extraction regular expression.
func (r *request) compileAndValidate() error {
	u, err := url.Parse(r.Path)
	if err != nil || !strings.HasPrefix(r.Path, "/") || u.Host != "" {
		return errInvalidURL
	}

	if r.ExtractionRegex == "" {
		return errNoExtractionRegex
	}

	rex, err := regexp.Compile(r.ExtractionRegex)
	if err != nil {
		return err
	}

	r.rex = rex
	return nil
}

// containsPlaceholder checks if the given placeholder exists in the Path, Body, or any Header.
func (r *request) containsPlaceholder(placeholder string) bool {
	if strings.Contains(r.Path, placeholder) || strings.Contains(r.Body, placeholder) {
		return true
	}
	for _, h := range r.Headers {
		if strings.Contains(h.Value, placeholder) {
			return true
		}
	}
	return false
}

// isFormURLEncoded reports whether the request has an application/x-www-form-urlencoded Content-Type header.
func (r *request) isFormURLEncoded() bool {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, "Content-Type") && strings.Contains(strings.ToLower(h.Value), "application/x-www-form-urlencoded") {
			return true
		}
	}
	return false
}

var passwordInputRegex = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password["']?`)

// isLoginFormPersisting reports whether body contains an active password input field.
func isLoginFormPersisting(body []byte) bool {
	return passwordInputRegex.Match(body)
}

// response represents the result of executing an HTTP request in a strategy.
type response struct {
	// Extraction is the substring matched by the ExtractionRegex capturing group,
	// or nil if no match occurred in the response body.
	Extraction *string
	// StatusCode is the HTTP status code returned by the server.
	StatusCode int
	// Body is the raw response body read from the server.
	Body []byte
}

// do executes the request and performs the extraction specified in the ExtractionRegex.
// The provided substitutions are used to replace placeholders in both the body and path.
func (r *request) do(ctx context.Context, cfg *config.Config, service *nspb.NetworkService, client goohttp.Client, substitutions map[string]string) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.TimeoutPerRequest())
	defer cancel()

	req, err := r.buildHTTPRequest(ctx, service, substitutions)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var extraction *string
	matches := r.rex.FindSubmatch(body)
	if len(matches) == 1 {
		// If the LLM provided a regex without a capturing group, len(matches) will be 1.
		// We fall back to the full match instead of failing.
		s := string(matches[0])
		extraction = &s
	} else if len(matches) > 1 {
		// Normally, the LLM provides exactly one capturing group, so we return matches[1].
		s := string(matches[1])
		extraction = &s
	}

	return &response{
		Extraction: extraction,
		StatusCode: resp.StatusCode,
		Body:       body,
	}, nil
}

// buildHTTPRequest constructs the underlying http.Request and applies the substitutions.
func (r *request) buildHTTPRequest(ctx context.Context, service *nspb.NetworkService, substitutions map[string]string) (*http.Request, error) {
	webroot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return nil, err
	}

	reqURL := webroot + substitute(r.Path, substitutions, true)

	var bodyReader io.Reader
	if r.Body != "" {
		escape := r.isFormURLEncoded()
		bodyReader = strings.NewReader(substitute(r.Body, substitutions, escape))
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for _, header := range r.Headers {
		// LLMs tend to add an empty header.
		if header.Name == "" {
			continue
		}

		value := substitute(header.Value, substitutions, false)
		req.Header.Set(header.Name, value)
	}

	return req, nil
}

// substitute replaces the placeholders in the string s with the provided substitutions.
// If escape is true, values are URL query escaped.
func substitute(s string, substitutions map[string]string, escape bool) string {
	for k, v := range substitutions {
		val := v
		if escape {
			val = url.QueryEscape(v)
		}
		s = strings.ReplaceAll(s, "[["+k+"]]", val)
	}
	return s
}

// header for an HTTP request.
type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
