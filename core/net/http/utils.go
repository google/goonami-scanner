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
	"io"
	"net/http"
)

// ReadBody reads the body of an HTTP response up to a maximum size. Note that if the response is
// exactly of the maximum size, this function will return an error.
func ReadBody(resp *http.Response, maxsize int) ([]byte, error) {
	buffer := make([]byte, maxsize)
	n, err := io.ReadFull(resp.Body, buffer)

	// We expect an ErrUnexpectedEOF error here (ironic, uh?). If we do not see that error, that means
	// that there is more to read on the page than our buffer (which is the maximum we want to read).
	if err == nil {
		return nil, ErrPageTooBig
	}

	// Something went wrong.
	if err != io.ErrUnexpectedEOF {
		return nil, err
	}

	return buffer[:n], nil
}
