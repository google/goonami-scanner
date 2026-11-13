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

package cache

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
)

// CachedResponse stores an HTTP response and its body in memory.
type CachedResponse struct {
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte
	URL        *url.URL
	Method     string
}

// Response returns a new http.Response with an open, readable Body.
func (c *CachedResponse) Response() *http.Response {
	return &http.Response{
		StatusCode: c.StatusCode,
		Status:     c.Status,
		Header:     c.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(c.Body)),
	}
}
