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
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		enforce bool
		maxSize int64
		want    *Storage
	}{
		{
			name:    "when_enforcement_is_enabled_it_returns_storage_with_enforcement",
			enforce: true,
			maxSize: 100,
			want: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 0,
			},
		},
		{
			name:    "when_enforcement_is_disabled_it_returns_storage_without_enforcement",
			enforce: false,
			maxSize: 0,
			want: &Storage{
				enforce:     false,
				maxSize:     0,
				usedStorage: 0,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := New(tc.enforce, tc.maxSize)
			if got.enforce != tc.want.enforce {
				t.Errorf("New(%v, %d) enforce = %v, want %v", tc.enforce, tc.maxSize, got.enforce, tc.want.enforce)
			}
			if got.maxSize != tc.want.maxSize {
				t.Errorf("New(%v, %d) maxSize = %v, want %v", tc.enforce, tc.maxSize, got.maxSize, tc.want.maxSize)
			}
			if got.usedStorage != tc.want.usedStorage {
				t.Errorf("New(%v, %d) usedStorage = %v, want %v", tc.enforce, tc.maxSize, got.usedStorage, tc.want.usedStorage)
			}
		})
	}
}

func TestStorage_Reserve(t *testing.T) {
	tests := []struct {
		name          string
		storage       *Storage
		size          int64
		wantResult    bool
		wantUsedSpace int64
	}{
		{
			name: "when_enforcement_is_disabled_reserve_returns_true",
			storage: &Storage{
				enforce:     false,
				maxSize:     100,
				usedStorage: 0,
			},
			size:          10,
			wantResult:    true,
			wantUsedSpace: 0,
		},
		{
			name: "when_requested_size_is_below_limit_reserve_returns_true",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 0,
			},
			size:          10,
			wantResult:    true,
			wantUsedSpace: 10,
		},
		{
			name: "when_requested_size_is_above_limit_reserve_returns_false",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 0,
			},
			size:          110,
			wantResult:    false,
			wantUsedSpace: 0,
		},
		{
			name: "when_requested_size_is_exactly_the_limit_reserve_returns_true",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 0,
			},
			size:          100,
			wantResult:    true,
			wantUsedSpace: 100,
		},
		{
			name: "when_usage_plus_requested_size_is_at_limit_reserve_returns_true",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 50,
			},
			size:          50,
			wantResult:    true,
			wantUsedSpace: 100,
		},
		{
			name: "when_usage_plus_requested_size_is_above_limit_reserve_returns_false",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 50,
			},
			size:          51,
			wantResult:    false,
			wantUsedSpace: 50,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.storage.Reserve(tc.size)
			if got != tc.wantResult {
				t.Errorf("Reserve(%d) = %v, want %v", tc.size, got, tc.wantResult)
			}
			if tc.storage.usedStorage != tc.wantUsedSpace {
				t.Errorf("usedStorage = %d, want %d", tc.storage.usedStorage, tc.wantUsedSpace)
			}
		})
	}
}

func TestStorage_Release(t *testing.T) {
	tests := []struct {
		name          string
		storage       *Storage
		size          int64
		wantUsedSpace int64
	}{
		{
			name: "when_enforcement_is_disabled_release_does_not_change_usage",
			storage: &Storage{
				enforce:     false,
				maxSize:     100,
				usedStorage: 0,
			},
			size:          10,
			wantUsedSpace: 0,
		},
		{
			name: "when_enforcement_is_enabled_release_reduces_usage",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 100,
			},
			size:          10,
			wantUsedSpace: 90,
		},
		{
			name: "when_releasing_entire_usage_returns_zero_usage",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 10,
			},
			size:          10,
			wantUsedSpace: 0,
		},
		{
			name: "when_releasing_more_than_usage_returns_zero_usage",
			storage: &Storage{
				enforce:     true,
				maxSize:     100,
				usedStorage: 10,
			},
			size:          20,
			wantUsedSpace: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.storage.Release(tc.size)
			if tc.storage.usedStorage != tc.wantUsedSpace {
				t.Errorf("usedStorage = %d, want %d", tc.storage.usedStorage, tc.wantUsedSpace)
			}
		})
	}
}
