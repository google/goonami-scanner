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

package hash

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprints_go_proto"
	"github.com/twmb/murmur3"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatalf("NewRegistry() returned nil")
	}
	if r.knownHashes == nil {
		t.Errorf("NewRegistry() did not initialize knownHashes map")
	}
}

func TestRegistryLoad(t *testing.T) {
	tests := []struct {
		name              string
		fingerprints      []*fpb.Fingerprints
		wantHashCount     int
		wantRegistryState map[uint64]*Identity
	}{
		{
			name:              "when_fingerprints_is_empty_returns_empty_registry",
			fingerprints:      []*fpb.Fingerprints{fpb.Fingerprints_builder{}.Build()},
			wantHashCount:     0,
			wantRegistryState: map[uint64]*Identity{},
		},
		{
			name: "when_loading_hash_versions_it_populates_registry",
			fingerprints: []*fpb.Fingerprints{
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
					HashVersions: []*fpb.HashVersion{
						hashVersion("hash1", []string{"1.0", "1.1"}),
					},
				}.Build(),
			},
			wantHashCount: 1,
			wantRegistryState: map[uint64]*Identity{
				murmur3.Sum64([]byte("hash1")): &Identity{
					Software: "sw1",
					Versions: []string{"1.0", "1.1"},
				},
			},
		},
		{
			name: "when_loading_content_hashes_it_populates_registry",
			fingerprints: []*fpb.Fingerprints{
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
					ContentHashes: []*fpb.ContentHash{
						contentHash("/path1", []string{"hash1"}),
					},
				}.Build(),
			},
			wantHashCount: 1,
			wantRegistryState: map[uint64]*Identity{
				murmur3.Sum64([]byte("hash1")): &Identity{Software: "sw1", PotentialRoots: []string{"/path1"}},
			},
		},
		{
			name: "when_loading_both_hash_and_content_hashes_it_populates_registry",
			fingerprints: []*fpb.Fingerprints{
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
					HashVersions: []*fpb.HashVersion{
						hashVersion("hash1", []string{"1.0"}),
					},
					ContentHashes: []*fpb.ContentHash{
						contentHash("/path1", []string{"hash2"}),
					},
				}.Build(),
			},
			wantHashCount: 2,
			wantRegistryState: map[uint64]*Identity{
				murmur3.Sum64([]byte("hash1")): &Identity{Software: "sw1", Versions: []string{"1.0"}},
				murmur3.Sum64([]byte("hash2")): &Identity{Software: "sw1", PotentialRoots: []string{"/path1"}},
			},
		},
		{
			name: "when_hash_collision_occurs_with_different_software_it_marks_as_invalid",
			fingerprints: []*fpb.Fingerprints{
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
					HashVersions: []*fpb.HashVersion{
						hashVersion("hash1", []string{"1.0"}),
					},
				}.Build(),
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw2"}.Build(),
					ContentHashes: []*fpb.ContentHash{
						contentHash("/path1", []string{"hash1"}),
					},
				}.Build(),
			},
			wantHashCount: 1,
			wantRegistryState: map[uint64]*Identity{
				murmur3.Sum64([]byte("hash1")): nil,
			},
		},
		{
			name: "when_loading_duplicate_versions_and_paths_it_deduplicates",
			fingerprints: []*fpb.Fingerprints{
				fpb.Fingerprints_builder{
					SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
					HashVersions: []*fpb.HashVersion{
						hashVersion("hash1", []string{"1.0", "1.0"}),
					},
					ContentHashes: []*fpb.ContentHash{
						contentHash("/path1", []string{"hash1"}),
						contentHash("/path1", []string{"hash1"}),
					},
				}.Build(),
			},
			wantHashCount: 1,
			wantRegistryState: map[uint64]*Identity{
				murmur3.Sum64([]byte("hash1")): &Identity{Software: "sw1", Versions: []string{"1.0"}, PotentialRoots: []string{"/path1"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			for _, fp := range tc.fingerprints {
				if err := r.Load(fp); err != nil {
					t.Fatalf("Load(%v) returned unexpected error: %v", fp, err)
				}
			}

			if got := r.Count(); got != tc.wantHashCount {
				t.Errorf("Count() = %d, want %d", got, tc.wantHashCount)
			}

			if diff := cmp.Diff(tc.wantRegistryState, r.knownHashes); diff != "" {
				t.Errorf("Registry state differs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRegistryFind(t *testing.T) {
	r := NewRegistry()
	fingerprints := fpb.Fingerprints_builder{
		SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw1"}.Build(),
		HashVersions: []*fpb.HashVersion{
			hashVersion("hash1", []string{"1.0"}),
		},
		ContentHashes: []*fpb.ContentHash{
			contentHash("path1", []string{"hash2"}),
			contentHash("path2", []string{"hash2"}),
			contentHash("imgs/logo.png", []string{"hash3"}),
			contentHash("collide/sw1", []string{"hashcollide"}),
		},
	}.Build()
	if err := r.Load(fingerprints); err != nil {
		t.Fatalf("Load(...) returned unexpected error: %v", err)
	}
	fingerprintsMulti := fpb.Fingerprints_builder{
		SoftwareIdentity: fpb.SoftwareIdentity_builder{Software: "sw2"}.Build(),
		ContentHashes: []*fpb.ContentHash{
			contentHash("bar/foo", []string{"hash4"}),
			contentHash("foo", []string{"hash4"}),
			contentHash("collide/sw2", []string{"hashcollide"}),
		},
	}.Build()
	if err := r.Load(fingerprintsMulti); err != nil {
		t.Fatalf("Load(...) returned unexpected error: %v", err)
	}

	tests := []struct {
		name string
		hash string
		path string
		want *Identity
	}{
		{
			name: "when_hash_is_not_found_returns_nil",
			hash: "unknown_hash",
			path: "/",
			want: nil,
		},
		{
			name: "when_hash_has_versions_but_no_roots_returns_identity_with_versions",
			hash: "hash1",
			path: "/",
			want: &Identity{Software: "sw1", Versions: []string{"1.0"}},
		},
		{
			name: "when_path_mismatches_it_returns_nil",
			hash: "hash2",
			path: "/otherpath",
			want: nil,
		},
		{
			name: "when_path_matches_exactly_it_returns_identity_with_root",
			hash: "hash2",
			path: "/path1",
			want: &Identity{Software: "sw1", PotentialRoots: []string{"/"}},
		},
		{
			name: "when_path_matches_as_suffix_it_returns_identity_with_root",
			hash: "hash2",
			path: "/app/path1",
			want: &Identity{Software: "sw1", PotentialRoots: []string{"/app/"}},
		},
		{
			name: "when_hash_has_multiple_roots_and_path_matches_it_returns_identity_with_root_1",
			hash: "hash2",
			path: "/a/b/path1",
			want: &Identity{Software: "sw1", PotentialRoots: []string{"/a/b/"}},
		},
		{
			name: "when_hash_has_multiple_roots_and_path_matches_it_returns_identity_with_root_2",
			hash: "hash2",
			path: "/a/b/path2",
			want: &Identity{Software: "sw1", PotentialRoots: []string{"/a/b/"}},
		},
		{
			name: "when_request_path_equals_content_path_returns_identity_with_slash_root",
			hash: "hash3",
			path: "/imgs/logo.png",
			want: &Identity{Software: "sw1", PotentialRoots: []string{"/"}},
		},
		{
			name: "when_multiple_roots_match_it_returns_identity_with_all_matching_roots",
			hash: "hash4",
			path: "/a/bar/foo",
			want: &Identity{Software: "sw2", PotentialRoots: []string{"/a/", "/a/bar/"}},
		},
		{
			name: "when_hash_collision_occurs_with_different_software_returns_nil",
			hash: "hashcollide",
			path: "/collide/sw1",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Find(tc.hash, tc.path)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Find(%q, %q) returned diff (-want +got):\n%s", tc.hash, tc.path, diff)
			}
		})
	}
}

func hashVersion(hash string, versions []string) *fpb.HashVersion {
	var vers []*fpb.Version
	for _, v := range versions {
		vers = append(vers, fpb.Version_builder{FullName: v}.Build())
	}
	return fpb.HashVersion_builder{
		Hash:     fpb.Hash_builder{HexString: hash}.Build(),
		Versions: vers,
	}.Build()
}

func contentHash(path string, hashes []string) *fpb.ContentHash {
	var hs []*fpb.Hash
	for _, h := range hashes {
		hs = append(hs, fpb.Hash_builder{HexString: h}.Build())
	}
	return fpb.ContentHash_builder{
		ContentPath: path,
		Hashes:      hs,
	}.Build()
}
