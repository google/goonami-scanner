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

// Package storage provides a storage manager for the webidentity fingerprinter.
package storage

import (
	"sync"
)

// Storage keeps track of the overall storage limitations (space).
type Storage struct {
	enforce     bool
	maxSize     int64
	mut         sync.Mutex
	usedStorage int64
}

// New returns a new instance of the storage manager.
func New(enforce bool, maxSize int64) *Storage {
	return &Storage{
		enforce:     enforce,
		maxSize:     maxSize,
		usedStorage: 0,
	}
}

// Reserve some storage space and fails if the limit is reached.
func (s *Storage) Reserve(size int64) bool {
	if !s.enforce {
		return true
	}

	s.mut.Lock()
	defer s.mut.Unlock()

	newsize := s.usedStorage + size
	if newsize > s.maxSize {
		return false
	}

	s.usedStorage = newsize
	return true
}

// Release some storage space.
func (s *Storage) Release(size int64) {
	if !s.enforce {
		return
	}

	s.mut.Lock()
	defer s.mut.Unlock()

	if s.usedStorage < size {
		s.usedStorage = 0
		return
	}

	s.usedStorage -= size
}
