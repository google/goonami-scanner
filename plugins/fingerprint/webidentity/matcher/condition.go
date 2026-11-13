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
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

type compiledCondition struct {
	header *compiledHeaderCondition
	body   *compiledBodyCondition
	hash   *compiledHashCondition
}

func (cc *compiledCondition) matches(resp *http.Response, body []byte, hashes *responseHashes) (bool, error) {
	if cc.header != nil {
		return cc.header.matches(resp), nil
	}
	if cc.body != nil {
		return cc.body.matches(body), nil
	}
	if cc.hash != nil {
		return cc.hash.matches(resp, body, hashes)
	}
	return true, nil
}

type compiledHeaderCondition struct {
	name     string
	contains string
	re       *regexp.Regexp
}

func (chc *compiledHeaderCondition) matches(resp *http.Response) bool {
	vals := headerValues(resp.Header, chc.name)
	if len(vals) == 0 {
		return false
	}
	if chc.contains == "" && chc.re == nil {
		return true
	}
	combined := strings.Join(vals, ", ")
	if chc.contains != "" && !strings.Contains(combined, chc.contains) {
		return false
	}
	if chc.re != nil && !chc.re.MatchString(combined) {
		return false
	}
	return true
}

type compiledBodyCondition struct {
	contains []byte
	re       *regexp.Regexp
}

func (cbc *compiledBodyCondition) matches(body []byte) bool {
	if len(cbc.contains) > 0 && !bytes.Contains(body, cbc.contains) {
		return false
	}
	if cbc.re != nil && !cbc.re.Match(body) {
		return false
	}
	return true
}

type compiledHashCondition struct {
	murmur3Hashes    map[string]bool
	bodySHA256Hashes map[string]bool
}

func (chc *compiledHashCondition) matches(resp *http.Response, body []byte, hashes *responseHashes) (bool, error) {
	if len(chc.murmur3Hashes) > 0 {
		m3, err := hashes.murmur3Hash(resp, body)
		if err != nil {
			return false, err
		}
		if chc.murmur3Hashes[m3] {
			return true, nil
		}
	}
	if len(chc.bodySHA256Hashes) > 0 {
		sha := hashes.sha256Hash(body)
		if chc.bodySHA256Hashes[sha] {
			return true, nil
		}
	}
	return false, nil
}

func compileConditions(conds []*fpb.HttpResponse_Expectation) ([]*compiledCondition, error) {
	res := make([]*compiledCondition, 0, len(conds))
	for i, c := range conds {
		cc, err := compileCondition(c)
		if err != nil {
			return nil, fmt.Errorf("condition %d: %w", i, err)
		}
		res = append(res, cc)
	}
	return res, nil
}

func compileCondition(e *fpb.HttpResponse_Expectation) (*compiledCondition, error) {
	if e == nil {
		return &compiledCondition{}, nil
	}
	var re *regexp.Regexp
	if e.GetRegexp() != "" {
		var err error
		re, err = regexp.Compile(e.GetRegexp())
		if err != nil {
			return nil, fmt.Errorf("invalid regexp %q: %w", e.GetRegexp(), err)
		}
	}

	if h := e.GetHeader(); h != nil {
		return &compiledCondition{
			header: &compiledHeaderCondition{
				name:     h.GetName(),
				contains: e.GetContains(),
				re:       re,
			},
		}, nil
	}
	if hc := e.GetHash(); hc != nil {
		return &compiledCondition{
			hash: compileHashCondition(hc),
		}, nil
	}
	if b := e.GetBody(); b != nil || e.GetContains() != "" || re != nil {
		return &compiledCondition{
			body: compileBodyCondition(e.GetContains(), re),
		}, nil
	}
	return &compiledCondition{}, nil
}

func compileHashCondition(hc *fpb.HttpResponse_Hash) *compiledHashCondition {
	return &compiledHashCondition{
		murmur3Hashes:    normalizeHashSet(hc.GetMurmur3Hashes()),
		bodySHA256Hashes: normalizeHashSet(hc.GetBodySha256Hashes()),
	}
}

func compileBodyCondition(contains string, re *regexp.Regexp) *compiledBodyCondition {
	var containsBytes []byte
	if contains != "" {
		containsBytes = []byte(contains)
	}
	return &compiledBodyCondition{
		contains: containsBytes,
		re:       re,
	}
}

func normalizeHashSet(hashes []string) map[string]bool {
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		set[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return set
}

func headerValues(h http.Header, name string) []string {
	if h == nil || name == "" {
		return nil
	}
	if vals := h.Values(name); len(vals) > 0 {
		return vals
	}
	for k, vals := range h {
		if strings.EqualFold(k, name) {
			return vals
		}
	}
	return nil
}
