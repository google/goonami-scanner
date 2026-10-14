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
	"net/url"
	"path"
	"regexp"
	"slices"
)

var (
	defaultForbiddenPathPatterns = []string{
		`(?:^|[^a-zA-Z])(?i:abort(?:quit)*)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:delete)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:drop)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:(?:hup)+)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:kill(?:all)?)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:(?:quit)+)(?:[^a-zA-Z]|$)`,
		`(?:^|[^a-zA-Z])(?i:remove)(?:[^a-zA-Z]|$)`,
	}

	defaultForbiddenPaths = func() []*regexp.Regexp {
		var compiled []*regexp.Regexp
		for _, p := range defaultForbiddenPathPatterns {
			compiled = append(compiled, regexp.MustCompile(p))
		}
		return compiled
	}()
)

// DefaultForbiddenPathPatterns returns the default regular expressions for blocking destructive or
// server-terminating HTTP paths across crawlers and LLM tools. Each pattern is case-insensitive on
// the action keyword and anchored on non-alphabetic word boundaries so benign words containing
// those substrings (such as "/skill.md", "/static/dropdown.js", "/img/backdrop.png", or
// "/equity/overview") are allowed while delimited paths and lifecycle endpoints ("/abortquitquit",
// "/quitquitquit", "/huphuphup", "/killall") are blocked.
func DefaultForbiddenPathPatterns() []string {
	return slices.Clone(defaultForbiddenPathPatterns)
}

// IsURLPathForbidden reports whether targetURL's canonicalized path or query matches any of the
// forbidden regular expressions. Only the URL path and query are evaluated (never the scheme or
// host/authority), and percent-encoded sequences and relative segments are normalized before
// matching so encoded paths (such as "/%6b%69%6c%6c") cannot bypass the filter.
func IsURLPathForbidden(targetURL *url.URL, forbidden []*regexp.Regexp) bool {
	if targetURL == nil || len(forbidden) == 0 {
		return false
	}

	candidate := path.Clean("/" + targetURL.Path)
	if targetURL.RawQuery != "" {
		unescapedQuery, err := url.QueryUnescape(targetURL.RawQuery)
		if err != nil {
			unescapedQuery = targetURL.RawQuery
		}
		candidate += "?" + unescapedQuery
	}

	for _, re := range forbidden {
		if re.MatchString(candidate) {
			return true
		}
	}
	return false
}
