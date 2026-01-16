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

// Package hash abstracts away the hash computation for a fingerprint.
package hash

import (
	"encoding/binary"
	"fmt"
	"net/http"

	"github.com/twmb/murmur3"
)

// Hash is a hash object that can be used to fingerprint HTTP responses.
type Hash struct {
	hash murmur3.Hash128
}

// Identity of a specific web application.
type Identity struct {
	Software       string
	PotentialRoots []string
	Versions       []string
}

// FromResponse computes the hash for a given HTTP response and its content.
func FromResponse(resp *http.Response, content []byte) (*Hash, error) {
	hash := New(resp)
	if err := hash.Update(content); err != nil {
		return nil, err
	}
	return hash, nil
}

// New creates a new hash object.
func New(resp *http.Response) *Hash {
	mur := murmur3.New128()
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(resp.StatusCode))
	mur.Write(buf)
	mur.Write([]byte(resp.Header.Get("Content-Type")))
	return &Hash{mur}
}

// Update updates the hash with the given buffer.
func (s *Hash) Update(buffer []byte) error {
	_, err := s.hash.Write(buffer)
	return err
}

// Hex returns the hash as a hex string.
func (s *Hash) Hex() string {
	high, low := s.hash.Sum128()
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf, high)
	binary.LittleEndian.PutUint64(buf[8:], low)
	return fmt.Sprintf("%x", buf)
}
