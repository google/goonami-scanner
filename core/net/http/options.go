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

package http

import (
	"net"
	"net/url"
	"strings"

	"github.com/google/goonami-scanner/core/net/netendpoint"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// ClientOptions are the parameters that control the behavior of the HTTP client.
// Options are different from configuration as they are used to instantiate ephemeral clients with
// a specific behavior. This is useful for some specific modules.
type ClientOptions struct {
	// StoreCookies indicates whether the client should keep track of cookies.
	StoreCookies bool

	// Whether to verify TLS certificates. By default, the client does NOT verify TLS certificates.
	// That is because we want to scan targets that may not have valid certificates.
	EnforceTLSCertVerification bool

	// DisableFollowRedirects indicates whether the client should not follow HTTP redirects.
	DisableFollowRedirects bool

	// AllowedAuthorities restricts redirects to only targets whose authority (host:port or host)
	// is in this list. If empty, all redirects are allowed (unless DisableFollowRedirects is true).
	AllowedAuthorities []string
}

// DefaultClientOptions returns the default client options.
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		StoreCookies:               false,
		EnforceTLSCertVerification: false,
		DisableFollowRedirects:     false,
		AllowedAuthorities:         nil,
	}
}

// LoadAuthorities loads the allowed authorities from the given network service.
func (co *ClientOptions) LoadAuthorities(service *nspb.NetworkService) error {
	if !service.HasNetworkEndpoint() {
		return nil
	}

	auths, err := netendpoint.ToURIAuthorities(service.GetNetworkEndpoint())
	if err != nil {
		return err
	}

	co.AllowedAuthorities = auths
	return nil
}

// IsAuthorityAllowed checks if the target URL's authority is allowed according to the client
// options.
func (co *ClientOptions) IsAuthorityAllowed(targetURL *url.URL) bool {
	if len(co.AllowedAuthorities) == 0 {
		return true
	}

	targetHost := targetURL.Hostname()
	targetPort := targetURL.Port()
	if targetPort == "" {
		if strings.EqualFold(targetURL.Scheme, "https") {
			targetPort = "443"
		} else if strings.EqualFold(targetURL.Scheme, "http") {
			targetPort = "80"
		}
	}

	for _, auth := range co.AllowedAuthorities {
		if strings.EqualFold(targetURL.Host, auth) {
			return true
		}

		authHost, authPort, err := net.SplitHostPort(auth)
		if err != nil {
			authHost = strings.TrimSuffix(strings.TrimPrefix(auth, "["), "]")
			if strings.EqualFold(targetHost, authHost) {
				return true
			}
		} else {
			authHost = strings.TrimSuffix(strings.TrimPrefix(authHost, "["), "]")
			if strings.EqualFold(targetHost, authHost) && targetPort == authPort {
				return true
			}
		}
	}
	return false
}
