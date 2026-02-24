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
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRegisterAndGetInteractions(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Hour)
	cbid := "test_cbid"

	if err := s.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	if err := s.Register(cbid, DNSInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	got := s.Get(cbid)
	if len(got) != 2 {
		t.Fatalf("Get() returned %d interactions, want 2", len(got))
	}

	expected := []Interaction{
		Interaction{Type: HTTPInteraction},
		Interaction{Type: DNSInteraction},
	}

	sortSlices := cmpopts.SortSlices(func(a, b Interaction) bool {
		return a.Type < b.Type
	})
	if diff := cmp.Diff(expected, got, sortSlices, cmpopts.IgnoreFields(Interaction{}, "RecordTime")); diff != "" {
		t.Errorf("Get() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestRegisterDuplicateInteractionType(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Hour)
	cbid := "test_cbid"

	if err := s.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	if err := s.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	got := s.Get(cbid)
	if len(got) != 1 {
		t.Fatalf("Get() returned %d interactions, want 1", len(got))
	}
}

func TestRegisterUnknownInteractionType(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Hour)

	err := s.Register("test_cbid", UnknownInteraction)
	if !errors.Is(err, ErrUnknownInteractionType) {
		t.Errorf("Register() returned error: %v, want %v", err, ErrUnknownInteractionType)
	}
}

func TestGetNonExistentCbid(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Hour)
	got := s.Get("non_existent")
	if len(got) != 0 {
		t.Errorf("Get() returned %d interactions, want 0", len(got))
	}
}

func TestDeleteInteractions(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 1*time.Hour)
	cbid := "delete_me"
	if err := s.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	s.Delete(cbid)
	got := s.Get(cbid)
	if len(got) != 0 {
		t.Errorf("Get() after Delete() = %v, want nil", got)
	}
}

func TestCleanupBeforeTTLDoesNotDelete(t *testing.T) {
	s := NewInMemoryInteractionStore(t.Context(), 1*time.Hour, 5*time.Millisecond)
	cbid := "no_expire"

	if err := s.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	got := s.Get(cbid)
	if len(got) == 0 {
		t.Fatal("interaction should be present")
	}

	// Wait for cleanup
	time.Sleep(10 * time.Millisecond)

	got = s.Get(cbid)
	if len(got) == 0 {
		t.Fatal("interaction should still be present")
	}
}

func TestInteractionsExpireAfterTTL(t *testing.T) {
	store := NewInMemoryInteractionStore(t.Context(), 5*time.Millisecond, 5*time.Millisecond)

	cbid := "expire_me"
	if err := store.Register(cbid, HTTPInteraction); err != nil {
		t.Fatalf("Register() returned error: %v", err)
	}

	// Verify it's there
	got := store.Get(cbid)
	if len(got) == 0 {
		t.Fatal("interaction should be present")
	}

	// Wait for TTL and cleanup
	time.Sleep(10 * time.Millisecond)

	// Should be gone
	got = store.Get(cbid)
	if len(got) != 0 {
		t.Errorf("Get() after TTL should be empty, got %v", got)
	}
}
