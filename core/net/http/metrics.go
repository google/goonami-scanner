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
	"net/http"

	"github.com/google/goonami-scanner/core/metrics"
)

// metricsClient records the volume of outbound requests.
type metricsClient struct {
	wrapped Client
}

// Do records the request and delegates to the wrapped client.
//
// Only the volume and whether the request reached a response are recorded. The
// URL, the host, the method and the status code are all chosen by the target or
// the caller and describe the target rather than the scanner.
func (c *metricsClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.wrapped.Do(req)

	ctx := req.Context()
	metrics.HTTPRequests.Add(ctx, 1)

	if err != nil {
		metrics.HTTPRequestErrors.Add(ctx, 1, metrics.ErrorClass(err))
	}

	return resp, err
}
