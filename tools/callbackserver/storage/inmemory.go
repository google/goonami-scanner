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

package storage

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrUnknownInteractionType is returned when an unknown interaction type is provided.
	ErrUnknownInteractionType = errors.New("unknown interaction type")
)

// InMemoryInteractionStore is an in-memory implementation of InteractionStore.
type InMemoryInteractionStore struct {
	mu             sync.RWMutex
	storage        map[string][]Interaction
	interactionTTL time.Duration
}

// NewInMemoryInteractionStore creates a new InMemoryInteractionStore.
func NewInMemoryInteractionStore(ctx context.Context, ttl time.Duration, cleanupInterval time.Duration) *InMemoryInteractionStore {
	s := &InMemoryInteractionStore{
		storage:        make(map[string][]Interaction),
		interactionTTL: ttl,
	}

	go s.cleanupLoop(ctx, cleanupInterval)
	return s
}

// Register an interaction into the storage backend. Note that if an interaction of the same type
// already exists, we just refresh its record time.
func (s *InMemoryInteractionStore) Register(cbid string, interactionType InteractionType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if interactionType == UnknownInteraction {
		return ErrUnknownInteractionType
	}

	interaction := Interaction{
		Type:       interactionType,
		RecordTime: time.Now(),
	}

	refreshed := []Interaction{interaction}
	existings := s.storage[cbid]
	for _, interaction := range existings {
		if interaction.Type == interactionType {
			continue
		}

		refreshed = append(refreshed, interaction)
	}

	s.storage[cbid] = refreshed
	return nil
}

// Get retrieves all interactions associated with the given cbid.
func (s *InMemoryInteractionStore) Get(cbid string) []Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	interactions, ok := s.storage[cbid]
	if !ok {
		return nil
	}

	// Return a copy to avoid concurrent modification issues
	res := make([]Interaction, len(interactions))
	copy(res, interactions)
	return res
}

// Delete deletes all interactions associated with the given cbid.
func (s *InMemoryInteractionStore) Delete(cbid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.storage, cbid)
}

func (s *InMemoryInteractionStore) cleanupLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		if ctx.Err() != nil {
			return
		}

		s.cleanup()
	}
}

func (s *InMemoryInteractionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for cbid, interactions := range s.storage {
		var interacts []Interaction

		for _, interaction := range interactions {
			if !now.After(interaction.RecordTime.Add(s.interactionTTL)) {
				interacts = append(interacts, interaction)
			}
		}

		s.storage[cbid] = interacts
	}
}
