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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/hash"
)

type responseHashes struct {
	murmur3Computed bool
	murmur3         string
	sha256Computed  bool
	sha256          string
}

func (rh *responseHashes) murmur3Hash(resp *http.Response, body []byte) (string, error) {
	if rh.murmur3Computed {
		return rh.murmur3, nil
	}
	h, err := hash.FromResponse(resp, body)
	if err != nil {
		return "", err
	}
	rh.murmur3 = strings.ToLower(h.Hex())
	rh.murmur3Computed = true
	return rh.murmur3, nil
}

func (rh *responseHashes) sha256Hash(body []byte) string {
	if rh.sha256Computed {
		return rh.sha256
	}
	sum := sha256.Sum256(body)
	rh.sha256 = strings.ToLower(hex.EncodeToString(sum[:]))
	rh.sha256Computed = true
	return rh.sha256
}
