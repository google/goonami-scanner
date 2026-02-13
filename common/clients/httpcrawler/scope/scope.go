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

// Package scope provides utilities to limit the scope of an HTTP crawl.
package scope

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	cpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
)

var (
	// ErrParseURL is returned when an URL fails to parse.
	ErrParseURL = errors.New("failed to parse URL")
)

// Decision represents the decision of a scope match.
type Decision int

const (
	// DecisionUnknown represents an unknown decision.
	DecisionUnknown = iota

	// DecisionInScope means the target URL is in scope.
	DecisionInScope

	// DecisionDomainMismatch means the target URL domain does not match the scope domain.
	DecisionDomainMismatch

	// DecisionPathMismatch means the target URL path does not match the scope path.
	DecisionPathMismatch
)

// Scope represents a scope for an HTTP crawl.
type Scope struct {
	Domain string
	Path   string
}

// FromProto creates a Scope from a proto definition.
func FromProto(scope *cpb.HttpCrawlerClientConfig_Scope) *Scope {
	return &Scope{
		Domain: scope.GetDomain(),
		Path:   NormalizePath(scope.GetPath()),
	}
}

// FromURL creates a Scope from an URL.
func FromURL(targeturl string) (*Scope, error) {
	u, err := url.Parse(targeturl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseURL, err)
	}

	hostname := u.Hostname()
	if u.Port() != "" {
		hostname += ":" + u.Port()
	}

	return &Scope{
		Domain: hostname,
		Path:   NormalizePath(u.Path),
	}, nil
}

// Load several scopes both from the configuration and the seed URLs. The behavior is defined by the
// scope_policy field in the configuration.
func Load(cfg *cpb.HttpCrawlerClientConfig, urls []string) ([]*Scope, error) {
	var scopes []*Scope

	for _, scope := range cfg.GetScopes() {
		scopes = append(scopes, FromProto(scope))
	}

	if cfg.GetScopePolicy() == cpb.HttpCrawlerClientConfig_SCOPE_POLICY_CONFIG_ONLY {
		return scopes, nil
	}

	for _, seedURL := range urls {
		scope, err := FromURL(seedURL)
		if err != nil {
			return nil, err
		}

		scopes = append(scopes, scope)
	}

	return scopes, nil
}

// Matches returns true if the target URL matches the scope (is in scope).
func (cs *Scope) Matches(targetURL string) (bool, error) {
	scopeDecision, err := cs.Decision(targetURL)
	if err != nil {
		return false, err
	}

	inScope := scopeDecision == DecisionInScope
	return inScope, nil
}

// Decision returns the scope decision for the given URL.
func (cs *Scope) Decision(targetURL string) (Decision, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return DecisionUnknown, fmt.Errorf("%w: %v", ErrParseURL, err)
	}

	hostname := u.Hostname()
	if u.Port() != "" {
		hostname += ":" + u.Port()
	}

	if cs.Domain != hostname {
		return DecisionDomainMismatch, nil
	}

	path := NormalizePath(u.Path)
	if cs.Path != "" && !strings.HasPrefix(path, cs.Path) {
		return DecisionPathMismatch, nil
	}

	return DecisionInScope, nil
}

// NormalizePath of an URL before performing scope matching. We want to be sure that all URL paths
// are treated the same way before being used:
//   - We treat any path ending with `/` as being a directory;
//   - Otherwise if the path contains a dot, we treat it as a file and use the parent directory;
//   - Otherwise we just need to add a trailing slash to the path.
func NormalizePath(url string) string {
	if strings.HasSuffix(url, "/") {
		return url
	}

	base := path.Base(url)
	if base == "." || !strings.Contains(base, ".") {
		return url + "/"
	}

	parent := path.Dir(url)
	return parent + "/"
}

// MatchAnyScope returns whether the target URL matches any of the given scopes.
func MatchAnyScope(targetURL string, scopes []*Scope) (bool, error) {
	for _, scope := range scopes {
		match, err := scope.Matches(targetURL)
		if err != nil {
			return false, err
		}

		if match {
			return true, nil
		}
	}

	return false, nil
}
