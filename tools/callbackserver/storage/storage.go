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

// Package storage provides an interface for storing and retrieving interactions.
package storage

import (
	"time"
)

// InteractionType represents the type of an out-of-band interaction.
type InteractionType int

const (
	// UnknownInteraction should not be used.
	UnknownInteraction InteractionType = iota
	// HTTPInteraction is used to track HTTP interactions.
	HTTPInteraction
	// DNSInteraction is used to track DNS interactions.
	DNSInteraction
)

// Interaction represents a single out-of-band interaction.
type Interaction struct {
	Type       InteractionType
	RecordTime time.Time
}

// InteractionStore is the interface for TCS interaction backend storage.
type InteractionStore interface {
	// Register an interaction into the storage backend.
	Register(cbid string, interactionType InteractionType) error

	// Get retrieves all interactions associated with the given cbid.
	Get(cbid string) []Interaction

	// Delete deletes an interaction from the storage backend.
	Delete(cbid string)
}
