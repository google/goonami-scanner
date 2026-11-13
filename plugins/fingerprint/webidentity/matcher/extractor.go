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
	"fmt"
	"net/http"
	"regexp"
	"strings"

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

type compiledVersionExtractor struct {
	fromHeader     string
	re             *regexp.Regexp
	murmur3Hash    string
	bodySHA256Hash string
	staticVersions []string
}

func (cve *compiledVersionExtractor) extract(resp *http.Response, body []byte, hashes *responseHashes) ([]string, error) {
	if cve.re != nil {
		if val, ok := extractSubmatch(resp, body, cve.fromHeader, cve.re); ok {
			return []string{val}, nil
		}
		return nil, nil
	}

	if cve.murmur3Hash != "" {
		m3, err := hashes.murmur3Hash(resp, body)
		if err != nil {
			return nil, err
		}
		if m3 == cve.murmur3Hash {
			return cve.staticVersions, nil
		}
	}

	if cve.bodySHA256Hash != "" {
		sha := hashes.sha256Hash(body)
		if sha == cve.bodySHA256Hash {
			return cve.staticVersions, nil
		}
	}

	return nil, nil
}

func compileVersionExtractors(ves []*fpb.VersionExtractor) ([]*compiledVersionExtractor, error) {
	res := make([]*compiledVersionExtractor, 0, len(ves))
	for i, ve := range ves {
		cve := &compiledVersionExtractor{
			fromHeader:     ve.GetFromHeader().GetName(),
			murmur3Hash:    strings.ToLower(strings.TrimSpace(ve.GetMurmur3Hash())),
			bodySHA256Hash: strings.ToLower(strings.TrimSpace(ve.GetBodySha256Hash())),
			staticVersions: ve.GetStaticVersions(),
		}
		if ve.GetRegexp() != "" {
			re, err := regexp.Compile(ve.GetRegexp())
			if err != nil {
				return nil, fmt.Errorf("version extractor %d invalid regexp %q: %w", i, ve.GetRegexp(), err)
			}
			cve.re = re
		}
		res = append(res, cve)
	}
	return res, nil
}

func extractSubmatch(resp *http.Response, body []byte, fromHeader string, re *regexp.Regexp) (string, bool) {
	var target string
	if fromHeader != "" {
		vals := headerValues(resp.Header, fromHeader)
		target = strings.Join(vals, ", ")
	} else {
		target = string(body)
	}
	sub := re.FindStringSubmatch(target)
	if len(sub) > 1 && sub[1] != "" {
		return sub[1], true
	}
	if len(sub) > 0 && sub[0] != "" {
		return sub[0], true
	}
	return "", false
}
