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

package engine

import (
	"cmp"
	"slices"
	"strings"
)

// IdentificationResult represents a detected application on a specific candidate root.
type IdentificationResult struct {
	Software        string
	ApplicationRoot string
	Versions        []string
	MatchedSteps    []string
}

type matchState struct {
	software   string
	rootPath   string
	identified bool
	versions   []string
	versionSet map[string]bool
	steps      []string
	stepSet    map[string]bool
}

func newMatchState(software, rootPath string) *matchState {
	return &matchState{
		software:   software,
		rootPath:   rootPath,
		versionSet: make(map[string]bool),
		stepSet:    make(map[string]bool),
	}
}

func (s *matchState) recordSuccess(versions, steps []string) {
	s.identified = true
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if v != "" && !s.versionSet[v] {
			s.versionSet[v] = true
			s.versions = append(s.versions, v)
		}
	}
	for _, step := range steps {
		if step != "" && !s.stepSet[step] {
			s.stepSet[step] = true
			s.steps = append(s.steps, step)
		}
	}
}

func (s *matchState) isComplete() bool {
	return s.identified && len(s.versions) > 0
}

func (s *matchState) isIdentified() bool {
	return s.identified
}

func stateKey(software, root string) string {
	return software + ":" + root
}

func getOrCreateState(states map[string]*matchState, software, root string) *matchState {
	sk := stateKey(software, root)
	s, exists := states[sk]
	if !exists {
		s = newMatchState(software, root)
		states[sk] = s
	}
	return s
}

func mergeIdentifiedStates(states map[string]*matchState) []*matchState {
	var identifiedStates []*matchState
	for _, s := range states {
		if s.isIdentified() {
			identifiedStates = append(identifiedStates, s)
		}
	}

	// Sort by software, then by rootPath length ascending so parent roots precede subpaths.
	slices.SortFunc(identifiedStates, func(a, b *matchState) int {
		return cmp.Or(
			cmp.Compare(a.software, b.software),
			cmp.Compare(len(a.rootPath), len(b.rootPath)),
			cmp.Compare(a.rootPath, b.rootPath),
		)
	})

	var keptStates []*matchState
	for _, s := range identifiedStates {
		merged := false
		for _, parent := range keptStates {
			if parent.software == s.software && isSubpath(parent.rootPath, s.rootPath) {
				parent.recordSuccess(s.versions, s.steps)
				merged = true
				break
			}
		}
		if !merged {
			keptStates = append(keptStates, s)
		}
	}
	return keptStates
}

func toIdentificationResults(states []*matchState) []*IdentificationResult {
	var results []*IdentificationResult
	for _, s := range states {
		slices.Sort(s.versions)
		slices.Sort(s.steps)
		results = append(results, &IdentificationResult{
			Software:        s.software,
			ApplicationRoot: s.rootPath,
			Versions:        s.versions,
			MatchedSteps:    s.steps,
		})
	}

	slices.SortFunc(results, func(a, b *IdentificationResult) int {
		return cmp.Or(
			cmp.Compare(a.Software, b.Software),
			cmp.Compare(a.ApplicationRoot, b.ApplicationRoot),
		)
	})
	return results
}

// isSubpath reports whether child is equal to or a subpath under parent.
func isSubpath(parent, child string) bool {
	if parent == child {
		return true
	}
	if parent == "" {
		return strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}
