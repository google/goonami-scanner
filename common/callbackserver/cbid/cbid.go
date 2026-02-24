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

// Package cbid provides functions for generating and validating callback identifiers (CBID).
package cbid

import (
	"encoding/hex"
	"errors"
	"regexp"

	"golang.org/x/crypto/sha3"
)

var (
	// cbidPattern is a regular expression that matches a valid CBID.
	cbidPattern = regexp.MustCompile(`^[a-f0-9]{56}$`)

	// ErrInvalidCBID is returned when a CBID is invalid.
	ErrInvalidCBID = errors.New("invalid CBID")
)

// Generate generates a CBID from a secret string using SHA3-224.
func Generate(secret string) (string, error) {
	hash := sha3.New224()

	if _, err := hash.Write([]byte(secret)); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Validate checks if the given string is a valid CBID.
func Validate(cbid string) error {
	if !cbidPattern.MatchString(cbid) {
		return ErrInvalidCBID
	}

	return nil
}
