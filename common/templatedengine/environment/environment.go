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
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/goonami-scanner/common/clients/callbackserver"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/net/netservice"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

var variablePattern = regexp.MustCompile(`\{\{ ([a-zA-Z0-9_]+) \}\}`)

var (
	// ErrInvalidRegexp is returned when a regexp is invalid.
	ErrInvalidRegexp = errors.New("invalid regexp")

	// ErrFailedExtraction is returned when an extraction fails.
	ErrFailedExtraction = errors.New("failed extraction")
)

// Environment stores variables that are used by the templated detector.
type Environment struct {
	cfg  *config.Config
	vars map[string]string
}

// New creates a new environment.
func New(cfg *config.Config) *Environment {
	return &Environment{
		cfg:  cfg,
		vars: make(map[string]string),
	}
}

// InitializeFor initializes the environment for a specific network service.
func (e *Environment) InitializeFor(ctx context.Context, service *nspb.NetworkService) error {
	e.Set(VarUtilTimestamp, fmt.Sprintf("%d", time.Now().UnixMilli()))

	webRoot, err := netservice.BuildWebRoot(service)
	if err != nil {
		return err
	}

	e.Set(VarNetServiceBaseURL, webRoot)
	e.Set(VarNetServiceProtocol, strings.TrimSpace(service.GetTransportProtocol().String()))

	endpoint := service.GetNetworkEndpoint()
	e.Set(VarNetServiceHostname, strings.TrimSpace(endpoint.GetHostname().GetName()))
	e.Set(VarNetServicePort, fmt.Sprintf("%d", endpoint.GetPort().GetPortNumber()))
	e.Set(VarNetServiceIP, strings.TrimSpace(endpoint.GetIpAddress().GetAddress()))

	if err := e.callbackServerInitialization(ctx); err != nil {
		return err
	}

	for k, v := range e.vars {
		log.DebugContextf(ctx, log.DebugLevelRequest, "environment: %s = %s", k, v)
	}

	return nil
}

func (e *Environment) callbackServerInitialization(ctx context.Context) error {
	client := callbackserver.DefaultClient()
	if !client.IsCallbackServerEnabled() {
		return nil
	}

	secret, err := generateSecret(32)
	if err != nil {
		return err
	}

	uri, err := client.GetHTTPCallbackURI(secret)
	if err != nil {
		return err
	}

	u, err := url.Parse(uri)
	if err != nil {
		return err
	}

	e.Set(VarCallbackURI, uri)
	e.Set(VarCallbackSecret, secret)
	e.Set(VarCallbackPort, u.Port())
	e.Set(VarCallbackAddress, u.Hostname())

	if dns, err := client.GetDNSCallbackDomain(secret); err == nil {
		e.Set(VarCallbackDNS, dns)
	}

	return nil
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

		log.WarnContextf(ctx, "%q not found in environment", varName)
		return match
	})
}

// Extract performs regexp extraction of pattern in content and stores it in varname.
func (e *Environment) Extract(ctx context.Context, content, varname, pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidRegexp, pattern, err)
	}

	matches := re.FindStringSubmatch(content)
	if len(matches) < 2 {
		return fmt.Errorf("%w: %q using pattern %q", ErrFailedExtraction, varname, pattern)
	}

	e.vars[varname] = matches[1]
	return nil
}

// generateSecret of a given size. Note that the output is hex encoded, so from a string perspective
// it is double the size.
func generateSecret(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
