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

// Package matcher evaluates HTTP responses against declarative fingerprint conditions and workflows.
package matcher

import (
	"errors"
	"fmt"
	"net/http"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

// ErrNilResponse is returned when attempting to match against a nil HTTP response.
var ErrNilResponse = errors.New("http response cannot be nil")

// MatchResult holds the outcome of evaluating a step or matcher against an HTTP response.
type MatchResult struct {
	// Matched indicates whether all status code, condition, and extraction requirements were met.
	Matched bool
	// Versions contains all extracted version strings from successful version extractors.
	Versions []string
	// ExtractedVars contains variables extracted from the response for subsequent steps.
	ExtractedVars map[string]string
}

// CompiledResponseMatcher contains pre-compiled conditions and extractors for an HttpResponse.
type CompiledResponseMatcher struct {
	statusCodes       map[int32]bool
	expectAll         []*compiledCondition
	expectAny         []*compiledCondition
	expectNone        []*compiledCondition
	extractAll        []*compiledVariableExtraction
	extractAny        []*compiledVariableExtraction
	versionExtractors []*compiledVersionExtractor
	raw               *fpb.HttpResponse
}

// Raw returns the underlying protobuf HttpResponse.
func (crm *CompiledResponseMatcher) Raw() *fpb.HttpResponse {
	return crm.raw
}

// Match evaluates an HTTP response and body against all status code and condition requirements.
func (crm *CompiledResponseMatcher) Match(resp *http.Response, body []byte) (*MatchResult, error) {
	if resp == nil {
		return nil, ErrNilResponse
	}
	if len(crm.statusCodes) > 0 && !crm.statusCodes[int32(resp.StatusCode)] {
		return &MatchResult{Matched: false}, nil
	}

	hashes := &responseHashes{}
	matched, err := crm.matchesConditions(resp, body, hashes)
	if err != nil {
		return nil, err
	}
	if !matched {
		return &MatchResult{Matched: false}, nil
	}

	extractedVars, ok := crm.extractVariables(resp, body)
	if !ok {
		return &MatchResult{Matched: false}, nil
	}

	versions, err := crm.extractVersions(resp, body, hashes)
	if err != nil {
		return nil, err
	}

	return &MatchResult{
		Matched:       true,
		Versions:      versions,
		ExtractedVars: extractedVars,
	}, nil
}

func (crm *CompiledResponseMatcher) matchesConditions(resp *http.Response, body []byte, hashes *responseHashes) (bool, error) {
	for _, c := range crm.expectAll {
		matched, err := c.matches(resp, body, hashes)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}

	if len(crm.expectAny) > 0 {
		anyMatched := false
		for _, c := range crm.expectAny {
			matched, err := c.matches(resp, body, hashes)
			if err != nil {
				return false, err
			}
			if matched {
				anyMatched = true
				break
			}
		}
		if !anyMatched {
			return false, nil
		}
	}

	for _, c := range crm.expectNone {
		matched, err := c.matches(resp, body, hashes)
		if err != nil {
			return false, err
		}
		if matched {
			return false, nil
		}
	}

	return true, nil
}

func (crm *CompiledResponseMatcher) extractVariables(resp *http.Response, body []byte) (map[string]string, bool) {
	extractedVars := make(map[string]string)
	for _, ext := range crm.extractAll {
		val, ok := ext.extract(resp, body)
		if !ok {
			return nil, false
		}
		extractedVars[ext.variableName] = val
	}

	if len(crm.extractAny) > 0 {
		anyExtracted := false
		for _, ext := range crm.extractAny {
			val, ok := ext.extract(resp, body)
			if ok {
				extractedVars[ext.variableName] = val
				anyExtracted = true
			}
		}
		if !anyExtracted {
			return nil, false
		}
	}

	return extractedVars, true
}

func (crm *CompiledResponseMatcher) extractVersions(resp *http.Response, body []byte, hashes *responseHashes) ([]string, error) {
	var versions []string
	for _, ve := range crm.versionExtractors {
		extracted, err := ve.extract(resp, body, hashes)
		if err != nil {
			return nil, err
		}
		versions = append(versions, extracted...)
	}
	return versions, nil
}

// CompileResponseMatcher compiles a protobuf HttpResponse into an efficient in-memory matcher.
func CompileResponseMatcher(r *fpb.HttpResponse) (*CompiledResponseMatcher, error) {
	if r == nil {
		return &CompiledResponseMatcher{raw: r}, nil
	}

	statusCodes := make(map[int32]bool, len(r.GetStatusCodes()))
	for _, sc := range r.GetStatusCodes() {
		statusCodes[sc] = true
	}

	expectAll, err := compileConditions(r.GetExpectAll().GetConditions())
	if err != nil {
		return nil, fmt.Errorf("expect_all: %w", err)
	}

	expectAny, err := compileConditions(r.GetExpectAny().GetConditions())
	if err != nil {
		return nil, fmt.Errorf("expect_any: %w", err)
	}

	expectNone, err := compileConditions(r.GetExpectNone().GetConditions())
	if err != nil {
		return nil, fmt.Errorf("expect_none: %w", err)
	}

	extractAll, err := compileExtractPatterns(r.GetExtractAll().GetPatterns())
	if err != nil {
		return nil, fmt.Errorf("extract_all: %w", err)
	}

	extractAny, err := compileExtractPatterns(r.GetExtractAny().GetPatterns())
	if err != nil {
		return nil, fmt.Errorf("extract_any: %w", err)
	}

	ves, err := compileVersionExtractors(r.GetVersionExtractors())
	if err != nil {
		return nil, err
	}

	return &CompiledResponseMatcher{
		statusCodes:       statusCodes,
		expectAll:         expectAll,
		expectAny:         expectAny,
		expectNone:        expectNone,
		extractAll:        extractAll,
		extractAny:        extractAny,
		versionExtractors: ves,
		raw:               r,
	}, nil
}
