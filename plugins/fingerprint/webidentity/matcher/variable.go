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

	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
)

type compiledVariableExtraction struct {
	variableName string
	fromHeader   string
	re           *regexp.Regexp
}

func (cve *compiledVariableExtraction) extract(resp *http.Response, body []byte) (string, bool) {
	return extractSubmatch(resp, body, cve.fromHeader, cve.re)
}

func compileExtractPatterns(patterns []*fpb.HttpResponse_Extract) ([]*compiledVariableExtraction, error) {
	res := make([]*compiledVariableExtraction, 0, len(patterns))
	for i, ext := range patterns {
		if ext.GetVariableName() == "" {
			return nil, fmt.Errorf("extraction %d: variable_name is required", i)
		}
		if ext.GetRegexp() == "" {
			return nil, fmt.Errorf("extraction %d for %q: regexp is required", i, ext.GetVariableName())
		}
		re, err := regexp.Compile(ext.GetRegexp())
		if err != nil {
			return nil, fmt.Errorf("extraction %d for %q invalid regexp: %w", i, ext.GetVariableName(), err)
		}
		cve := &compiledVariableExtraction{
			variableName: ext.GetVariableName(),
			fromHeader:   ext.GetFromHeader().GetName(),
			re:           re,
		}
		res = append(res, cve)
	}
	return res, nil
}
