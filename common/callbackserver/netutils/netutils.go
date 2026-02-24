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

// Package netutils provides network utilities for the callback server.
package netutils

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/goonami-scanner/common/callbackserver/cbid"
	"github.com/google/goonami-scanner/core/net/iputils"
)

var (
	// ErrInvalidDomain is returned when the domain for a DNS callback is invalid.
	ErrInvalidDomain = errors.New("invalid domain for DNS callback")

	// ErrInvalidURL is returned when the URL for an HTTP callback is invalid.
	ErrInvalidURL = errors.New("invalid URL for HTTP callback")

	// ErrFailedToParseURL is returned when the URL for an HTTP callback cannot be parsed.
	ErrFailedToParseURL = errors.New("failed to parse URL for HTTP callback")
)

// CallbackURL returns the URL for the callback server for an HTTP callback.
func CallbackURL(host string, port int, cbid string) string {
	// TODO: b/487253053 - Add support for HTTPS.
	return fmt.Sprintf("http://%s:%d/%s", host, port, cbid)
}

// CallbackDomain returns the domain for the callback server for a DNS callback.
func CallbackDomain(cbid string, domain string) (string, error) {
	if iputils.IsIP(domain) {
		return "", fmt.Errorf("%w: %s", ErrInvalidDomain, domain)
	}

	return fmt.Sprintf("%s.%s", cbid, domain), nil
}

// IdentifierFromURL returns the identifier (CBID) extracted from a URL. Usually used with HTTP
// callbacks.
func IdentifierFromURL(httpURL string) (string, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedToParseURL, err)
	}

	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return "", ErrInvalidURL
	}

	if strings.Contains(path, "/") {
		return "", fmt.Errorf("%w: %s", ErrInvalidURL, httpURL)
	}

	if err := cbid.Validate(path); err != nil {
		return "", err
	}

	return path, nil
}

// IdentifierFromDomain returns the identifier (CBID) extracted from a domain. Usually used with
// DNS callbacks.
func IdentifierFromDomain(domain string) (string, error) {
	if iputils.IsIP(domain) {
		return "", fmt.Errorf("%w: %s", ErrInvalidDomain, domain)
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 || parts[0] == "" {
		return "", ErrInvalidDomain
	}

	id := parts[0]
	if err := cbid.Validate(id); err != nil {
		return "", err
	}

	return id, nil
}
