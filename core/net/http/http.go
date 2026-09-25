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

// Package http abstracts away HTTP clients so that they can be switched transparently.
package http

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/goonami-scanner/core/config"
)

var (
	// ErrPageTooBig is returned when the response body is larger than the maximum size.
	ErrPageTooBig = errors.New("page is too big")

	registryMut sync.RWMutex
	registry    = make(map[string]CreateHTTPClientFn)

	sharedClientMut sync.Once
	sharedClient    Client
)

// Client is the interface for HTTP clients.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// CreateHTTPClientFn is a function that creates a new HTTP Client.
type CreateHTTPClientFn func(*config.Config, *ClientOptions) (Client, error)

// Register registers a new HTTP client factory.
func Register(name string, factory CreateHTTPClientFn) {
	registryMut.Lock()
	defer registryMut.Unlock()
	registry[name] = factory
}

// NewClient returns an HTTP Client configured by the global configuration.
// If the configured client is not registered, it returns an error.
//
// The returned client is instrumented.
func NewClient(cfg *config.Config, options *ClientOptions) (Client, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	name := CurrentClientName(cfg)
	registryMut.RLock()
	factory, exists := registry[name]
	registryMut.RUnlock()

	if !exists {
		return nil, fmt.Errorf("http client %q is not registered", name)
	}

	client, err := factory(cfg, options)
	if err != nil {
		return nil, err
	}

	mc := &metricsClient{wrapped: client}
	if options == nil || !options.RetryOnRateLimit {
		return mc, nil
	}

	return &retriableClient{
		wrapped: mc,
		cfg:     cfg,
	}, nil
}

// SharedClient returns a shared HTTP Client configured by the global configuration with default
// options.
// If there is any issue creating the client, Goonami panics.
func SharedClient(cfg *config.Config) Client {
	sharedClientMut.Do(func() {
		var err error
		sharedClient, err = NewClient(cfg, DefaultClientOptions())
		if err != nil {
			panic(fmt.Sprintf("failed to create shared HTTP client: %v", err))
		}
	})

	return sharedClient
}

// CurrentClientName returns the name of the current HTTP client.
func CurrentClientName(cfg *config.Config) string {
	if name := cfg.GlobalConfig().GetHttpClient(); name != "" {
		return name
	}

	return "simpleclient"
}
