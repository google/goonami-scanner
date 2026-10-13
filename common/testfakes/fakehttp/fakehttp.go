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

// Package fakehttp provides a fake implementation of the Goonami HTTP client.
package fakehttp

import (
	"net/http"
	"sync"
)

// DoFn is the type of function that overrides the Do() method of the fake HTTP client.
type DoFn func(req *http.Request) (*http.Response, error)

// Client is a fake implementation of the Goonami HTTP client.
type Client struct {
	mu         sync.Mutex
	calls      int
	statusCode int
	err        error
	override   DoFn
}

// New creates a new fake HTTP client returning the given status code or error.
// When both statusCode is 0 and err is nil, Do returns (nil, nil).
func New(statusCode int, err error) *Client {
	return &Client{
		statusCode: statusCode,
		err:        err,
	}
}

// NewWithFunc creates a new fake HTTP client that delegates Do() to fn.
func NewWithFunc(fn DoFn) *Client {
	return &Client{
		override: fn,
	}
}

// OverrideDo overrides the Do() behavior of the fake HTTP client.
func (c *Client) OverrideDo(fn DoFn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.override = fn
}

// Calls returns the number of times Do() has been called on the fake HTTP client.
func (c *Client) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// Do executes the fake HTTP request.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls++
	override := c.override
	statusCode := c.statusCode
	err := c.err
	c.mu.Unlock()

	if override != nil {
		return override(req)
	}
	if err != nil {
		return nil, err
	}
	if statusCode == 0 {
		return nil, nil
	}
	return &http.Response{
		StatusCode: statusCode,
		Body:       http.NoBody,
	}, nil
}
