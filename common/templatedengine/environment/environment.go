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

// Package environment provides the environment used by the templated engine to store and manage variables.
package environment

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/net/netservice"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var variablePattern = regexp.MustCompile(`\{\{ ([a-zA-Z0-9_]+) \}\}`)

// Environment stores variables that are used by the templated detector.
type Environment struct {
	vars map[string]string
}

// New creates a new environment.
func New() *Environment {
	return &Environment{
		vars: make(map[string]string),
	}
}

// InitializeFor initializes the environment for a specific network service.
func (e *Environment) InitializeFor(ctx context.Context, service *nspb.NetworkService) {
	e.Set("T_UTL_CURRENT_TIMESTAMP_MS", fmt.Sprintf("%d", time.Now().UnixMilli()))

	webRoot, err := netservice.BuildWebRoot(service)
	if err == nil {
		e.Set("T_NS_BASEURL", webRoot)
	}

	e.Set("T_NS_PROTOCOL", strings.TrimSpace(service.GetTransportProtocol().String()))

	endpoint := service.GetNetworkEndpoint()
	e.Set("T_NS_HOSTNAME", strings.TrimSpace(endpoint.GetHostname().GetName()))
	e.Set("T_NS_PORT", fmt.Sprintf("%d", endpoint.GetPort().GetPortNumber()))
	e.Set("T_NS_IP", strings.TrimSpace(endpoint.GetIpAddress().GetAddress()))

	// TODO: b/483970797 - Add callback server variables when implemented in Goonami.

	for k, v := range e.vars {
		log.DebugContextf(ctx, log.DebugLevelRequest, "environment: %s = %s", k, v)
	}
}

// Set sets a variable in the environment.
func (e *Environment) Set(key, value string) {
	e.vars[key] = value
}

// Get gets a variable from the environment.
func (e *Environment) Get(key string) (string, bool) {
	v, ok := e.vars[key]
	return v, ok
}

// Substitute replaces variables in a template string.
func (e *Environment) Substitute(ctx context.Context, template string) string {
	return variablePattern.ReplaceAllStringFunc(template, func(match string) string {
		varName := variablePattern.FindStringSubmatch(match)[1]
		if val, ok := e.vars[varName]; ok {
			return val
		}

		log.WarnContextf(ctx, "substitution not found for '%s' in environment", varName)
		return match
	})
}

// Extract performs regexp extraction of pattern in content and stores it in varname.
func (e *Environment) Extract(ctx context.Context, content, varname, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.WarnContextf(ctx, "failed to compile regexp '%s': %v", pattern, err)
		return false
	}

	matches := re.FindStringSubmatch(content)
	if len(matches) < 2 {
		log.DebugContextf(ctx, log.DebugLevelRequest, "failed to extract variable '%s' from content using pattern '%s'", varname, pattern)
		return false
	}

	e.vars[varname] = matches[1]
	return true
}
