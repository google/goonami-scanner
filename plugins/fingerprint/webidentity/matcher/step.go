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

package matcher

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

var (
	// ErrNilStep is returned when compiling a nil Step.
	ErrNilStep = errors.New("step cannot be nil")
	// ErrMissingStepName is returned when compiling a Step with an empty name.
	ErrMissingStepName = errors.New("step name cannot be empty")
)

// CompiledStep contains pre-compiled patterns and response matchers for a Step.
type CompiledStep struct {
	name       string
	pathRegexp *regexp.Regexp
	matcher    *CompiledResponseMatcher
	raw        *fpb.Step
}

// Name returns the unique step name.
func (cs *CompiledStep) Name() string {
	return cs.name
}

// Matcher returns the compiled response matcher for this step.
func (cs *CompiledStep) Matcher() *CompiledResponseMatcher {
	return cs.matcher
}

// PathRegexp returns the compiled path regular expression, if defined.
func (cs *CompiledStep) PathRegexp() *regexp.Regexp {
	return cs.pathRegexp
}

// Raw returns the underlying protobuf step.
func (cs *CompiledStep) Raw() *fpb.Step {
	return cs.raw
}

// Match evaluates an HTTP response and body against this step's criteria and variable extractions.
func (cs *CompiledStep) Match(resp *http.Response, body []byte) (*MatchResult, error) {
	if resp == nil {
		return nil, ErrNilResponse
	}
	return cs.matcher.Match(resp, body)
}

// CompileStep compiles a protobuf Step, including its path regex, response matcher, and variable extractions.
func CompileStep(s *fpb.Step) (*CompiledStep, error) {
	if s == nil {
		return nil, ErrNilStep
	}
	if s.GetName() == "" {
		return nil, ErrMissingStepName
	}

	var pathRe *regexp.Regexp
	if s.GetPathRegexp() != "" {
		re, err := regexp.Compile(s.GetPathRegexp())
		if err != nil {
			return nil, fmt.Errorf("invalid path_regexp %q: %w", s.GetPathRegexp(), err)
		}
		pathRe = re
	}

	matcher, err := CompileResponseMatcher(s.GetResponse())
	if err != nil {
		return nil, err
	}

	return &CompiledStep{
		name:       s.GetName(),
		pathRegexp: pathRe,
		matcher:    matcher,
		raw:        s,
	}, nil
}
