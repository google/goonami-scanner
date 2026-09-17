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

package metrics

import "strings"

// maxLabelValueLength bounds the length of a label value.
const maxLabelValueLength = 128

// LabelKey is the name of a metric dimension. Keys are declared constants: see
// the catalog for the full set.
type LabelKey string

// Label is a single key/value dimension attached to an observation. Labels are
// built by the constructors in the catalog rather than directly, so that every
// value goes through a bounding or normalizing step.
type Label struct {
	Key   LabelKey
	Value string
}

// sanitizeValue bounds and normalizes a label value. Constructors in the catalog
// are expected to produce clean values already; this guarantees that even an
// unexpected one cannot break the series encoding or grow without bound.
func sanitizeValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}

	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, value)

	if len(value) > maxLabelValueLength {
		value = value[:maxLabelValueLength]
	}
	return value
}
