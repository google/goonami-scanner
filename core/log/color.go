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

package log

const (
	ansiReset      = "\033[0m"
	ansiBoldWhite  = "\033[1;37m"
	ansiBoldBlue   = "\033[1;34m"
	ansiBoldYellow = "\033[1;33m"
	ansiBoldRed    = "\033[1;31m"
	ansiBoldGray   = "\033[1;30m"
	ansiBoldGreen  = "\033[1;32m"
	ansiGreen      = "\033[0;32m"
	ansiBoldCyan   = "\033[1;36m"
	ansiCyan       = "\033[0;36m"
)

// colorize applies the given ANSI color to the string if enabled is true.
func colorize(s string, color string, enabled bool) string {
	if !enabled {
		return s
	}

	return color + s + ansiReset
}
