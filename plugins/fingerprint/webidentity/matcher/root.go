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

package matcher

import (
	"regexp"
	"strings"
)

// InferRootFromSuffix checks if crawledPath ends with suffix.
// If it does, it returns the inferred root path (normalized without trailing slash) and true.
func InferRootFromSuffix(crawledPath, suffix string) (string, bool) {
	if suffix == "" || !strings.HasSuffix(crawledPath, suffix) {
		return "", false
	}
	root := strings.TrimSuffix(crawledPath, suffix)
	root = strings.TrimRight(root, "/")
	return root, true
}

// InferRootFromRegexp checks if crawledPath matches the regular expression.
// If it contains a named capture group "root", that captured value is returned.
// Otherwise, the substring preceding the match is returned as the inferred root path.
func InferRootFromRegexp(crawledPath string, re *regexp.Regexp) (string, bool) {
	if re == nil {
		return "", false
	}
	loc := re.FindStringSubmatchIndex(crawledPath)
	if loc == nil {
		return "", false
	}
	for i, name := range re.SubexpNames() {
		if name == "root" && i*2 < len(loc) && loc[i*2] >= 0 {
			root := crawledPath[loc[i*2]:loc[i*2+1]]
			return strings.TrimRight(root, "/"), true
		}
	}
	root := crawledPath[:loc[0]]
	return strings.TrimRight(root, "/"), true
}
