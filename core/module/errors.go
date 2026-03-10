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

package module

import "errors"

var (
	// ErrFatal is returned when a fatal module error occurs. The scanner will stop
	// all processing when such an error is returned.
	ErrFatal = errors.New("fatal error")

	// ErrRecoverable is returned when a non-fatal module error occurs. The scanner will
	// be able to continue processing other services when such an error is returned.
	ErrRecoverable = errors.New("recoverable error")
)

// IsRecoverableErr returns true if the error is a recoverable module error and the scanner should
// continue processing other services.
func IsRecoverableErr(err error) bool {
	return errors.Is(err, ErrRecoverable)
}
