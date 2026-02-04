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

// Package http abstract away HTTP clients so that they can be switched transparently.
package http

import (
	"net/http"

	"github.com/google/goonami-scanner/core/config"
)

type NewClientFunc func(cfg *config.Config) (Client, error)

var defaultClientFunc NewClientFunc = nil

// Client is the interface for HTTP clients. Note that these clients will be wrappers in higher
// level constructs providing additional functionality (such as rate limiting).
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

var defaultClient Client = nil

// InitializeDefaults initializes the default HTTP client with a SimpleClient.
func InitializeDefaults(cfg *config.Config) error {
	client, err := NewRateLimitClient(cfg)
	if err != nil {
		return err
	}

	defaultClient = client
	return nil
}

// SetDefaultClient changes the default HTTP client used by Goonami.
func SetDefaultClient(client Client) {
	defaultClient = client
}

// DefaultClient returns the default HTTP client used by Goonami. This is what most modules in
// Goonami should use to perform HTTP requests. Note that if no custom client was bound or the
// defaults were not initialized, this function will panic.
func DefaultClient() Client {
	if defaultClient == nil {
		panic("no HTTP client was set/initialized, abort everything.")
	}

	return defaultClient
}
