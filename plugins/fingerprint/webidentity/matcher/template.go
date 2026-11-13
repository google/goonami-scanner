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

var variablePlaceholderRegex = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_-]+)\s*\}\}`)

// SubstituteVariables replaces occurrences of {{ var_name }} in template with values from vars.
func SubstituteVariables(template string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(template, "{{") {
		return template
	}
	return variablePlaceholderRegex.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.TrimSpace(match[2 : len(match)-2])
		if val, ok := vars[name]; ok {
			return val
		}
		return match
	})
}
