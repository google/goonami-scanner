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

// Package cache provides an in-memory HTTP response cache with request coalescing for web fingerprinting.
package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

const (
	// defaultMaxBodyBytes is the maximum number of bytes read from an active HTTP response (10 MB).
	defaultMaxBodyBytes = 10 * 1024 * 1024
)

var (
	// ErrNilRequest is returned when attempting to fetch with a nil HTTP request.
	ErrNilRequest = errors.New("http request cannot be nil")
	// ErrNoClient is returned when attempting to fetch without an HTTP client configured.
	ErrNoClient = errors.New("no http client configured for cache fetch")
)

// HTTPDoer executes HTTP requests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Cache provides thread-safe in-memory caching and singleflight request coalescing.
type Cache struct {
	mu           sync.RWMutex
	entries      map[string]*CachedResponse
	order        []*CachedResponse
	client       HTTPDoer
	group        singleflight.Group
	maxBodyBytes int64
}

// Option configures a Cache instance.
type Option func(*Cache)

// WithMaxBodyBytes sets the maximum body size read during active fetches.
func WithMaxBodyBytes(max int64) Option {
	return func(c *Cache) {
		if max > 0 {
			c.maxBodyBytes = max
		}
	}
}

// New creates a new Cache with the given HTTP client and options.
func New(client HTTPDoer, opts ...Option) *Cache {
	c := &Cache{
		entries:      make(map[string]*CachedResponse),
		client:       client,
		maxBodyBytes: defaultMaxBodyBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Put adds or updates a response in the cache.
func (c *Cache) Put(method, rawURL string, resp *http.Response, body []byte) *CachedResponse {
	key := normalizeKey(method, rawURL)
	parsedURL, _ := url.Parse(rawURL)

	statusCode := 200
	status := "200 OK"
	var header http.Header
	if resp != nil {
		statusCode = resp.StatusCode
		status = resp.Status
		header = resp.Header.Clone()
	} else {
		header = make(http.Header)
	}

	entry := &CachedResponse{
		StatusCode: statusCode,
		Status:     status,
		Header:     header,
		Body:       bytes.Clone(body),
		URL:        parsedURL,
		Method:     strings.ToUpper(method),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, exists := c.entries[key]; exists {
		if idx := slices.Index(c.order, prev); idx >= 0 {
			c.order[idx] = entry
		}
	} else {
		c.order = append(c.order, entry)
	}
	c.entries[key] = entry
	return entry
}

// Get looks up a cached response by method and URL.
func (c *Cache) Get(method, rawURL string) (*CachedResponse, bool) {
	key := normalizeKey(method, rawURL)
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	return entry, ok
}

// All returns a slice of all cached responses in insertion order.
func (c *Cache) All() []*CachedResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Clone(c.order)
}

// Fetch retrieves a response from cache or issues an HTTP request using singleflight coalescing.
func (c *Cache) Fetch(ctx context.Context, req *http.Request) (*CachedResponse, error) {
	if req == nil || req.URL == nil {
		return nil, ErrNilRequest
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	rawURL := req.URL.String()

	if entry, ok := c.Get(method, rawURL); ok {
		return entry, nil
	}

	if c.client == nil {
		return nil, ErrNoClient
	}

	key := normalizeKey(method, rawURL)
	res, err, _ := c.group.Do(key, func() (any, error) {
		// Double check after acquiring singleflight lock.
		if entry, ok := c.Get(method, rawURL); ok {
			return entry, nil
		}

		reqWithCtx := req.WithContext(ctx)
		resp, err := c.client.Do(reqWithCtx)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodyBytes))
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}

		return c.Put(method, rawURL, resp, body), nil
	})

	if err != nil {
		return nil, err
	}
	return res.(*CachedResponse), nil
}

func normalizeKey(method, rawURL string) string {
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return method + " " + rawURL
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return method + " " + parsed.String()
}
