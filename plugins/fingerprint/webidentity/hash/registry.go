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
	"slices"
	"strings"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprints_go_proto"
	"github.com/twmb/murmur3"
)

// Registry is a registry of known hashes and their associated identities.
type Registry struct {
	knownHashes map[uint64]*Identity
}

// NewRegistry creates a new registry object.
func NewRegistry() *Registry {
	return &Registry{
		knownHashes: make(map[uint64]*Identity),
	}
}

// Load the given hashes from a protobuf to the registry.
// Note that this function transforms the old storage format of Tsunami (hex string) to a lighter
// 64 bit uint hash. This increases the collision rate but significantly reduces the memory
// footprint (~26%). No collision were actually observed on existing fingerprints.
func (s *Registry) Load(fingerprints *fpb.Fingerprints) error {
	software := fingerprints.GetSoftwareIdentity().GetSoftware()
	for _, hv := range fingerprints.GetHashVersions() {
		hash := murmur3.Sum64([]byte(hv.GetHash().GetHexString()))
		s.addVersions(hash, software, hv.GetVersions())
	}

	for _, contentHash := range fingerprints.GetContentHashes() {
		path := contentHash.GetContentPath()
		for _, h := range contentHash.GetHashes() {
			hash := murmur3.Sum64([]byte(h.GetHexString()))
			s.addPath(hash, software, path)
		}
	}

	return nil
}

// Count the number of hashes in the registry.
func (s *Registry) Count() int {
	return len(s.knownHashes)
}

// Find the identity associated with a given hash and resource path.
// This function tries to match the most probable root paths for the web application and returns
// the candidates in the PotentialRoots field.
func (s *Registry) Find(hash string, path string) *Identity {
	inthash := murmur3.Sum64([]byte(hash))
	id, ok := s.knownHashes[inthash]
	if !ok || id == nil {
		return nil
	}

	var roots []string
	for _, p := range id.PotentialRoots {
		if strings.HasSuffix(path, p) {
			roots = append(roots, strings.TrimSuffix(path, p))
		}
	}

	// If we cannot infer the root, there might be an issue.
	if len(id.PotentialRoots) > 0 && len(roots) == 0 {
		return nil
	}

	return &Identity{
		Software:       id.Software,
		PotentialRoots: roots,
		Versions:       id.Versions,
	}
}

func (s *Registry) addVersions(hash uint64, software string, versions []*fpb.Version) {
	id := s.addSoftware(hash, software)
	if id == nil {
		return
	}

	for _, v := range versions {
		versionName := v.GetFullName()
		if !slices.Contains(id.Versions, versionName) {
			id.Versions = append(id.Versions, versionName)
		}
	}
}

func (s *Registry) addPath(hash uint64, software string, path string) {
	id := s.addSoftware(hash, software)
	if id == nil {
		return
	}

	if !slices.Contains(id.PotentialRoots, path) {
		id.PotentialRoots = append(id.PotentialRoots, path)
	}
}

// addSoftware registers the given hash to a specific software. If there is a conflict with another
// software, the hash is completely removed and ignored in the future.
func (s *Registry) addSoftware(hash uint64, software string) *Identity {
	id, ok := s.knownHashes[hash]
	if ok {
		if id == nil || id.Software != software {
			s.knownHashes[hash] = nil
			return nil
		}
	}

	if !ok {
		id = &Identity{
			Software: software,
		}
		s.knownHashes[hash] = id
	}

	return id
}
