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
	"cmp"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// ResponseCookies returns the active cookies in jar across all URLs visited in the redirect chain
// ending at resp (most recent hop first, followed by reqURL) and any explicit Set-Cookie paths on
// those responses, deduplicated by cookie name.
func ResponseCookies(jar http.CookieJar, reqURL *url.URL, resp *http.Response) []*http.Cookie {
	if jar == nil {
		return nil
	}
	seenURLs := make(map[string]bool)
	seenNames := make(map[string]bool)
	var cookies []*http.Cookie
	collect := func(u *url.URL) {
		if u == nil {
			return
		}
		key := u.Scheme + "://" + u.Host + cmp.Or(u.Path, "/")
		if seenURLs[key] {
			return
		}
		seenURLs[key] = true
		for _, c := range jar.Cookies(u) {
			if !seenNames[c.Name] {
				seenNames[c.Name] = true
				cookies = append(cookies, c)
			}
		}
	}
	for cur := resp; cur != nil; {
		u := reqURL
		if cur.Request != nil && cur.Request.URL != nil {
			u = cur.Request.URL
		}
		collect(u)
		if u != nil && len(cur.Header["Set-Cookie"]) > 0 {
			for _, sc := range cur.Cookies() {
				if strings.HasPrefix(sc.Path, "/") {
					cu := *u
					cu.Path, cu.RawPath = sc.Path, ""
					collect(&cu)
				}
			}
		}
		if cur.Request == nil {
			break
		}
		cur = cur.Request.Response
	}
	collect(reqURL)
	return cookies
}
