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

// Package engine orchestrates declarative web application fingerprinting across passive cache and active queries.
package engine

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
	fpb "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/fingerprint_go_proto"
	"github.com/google/goonami-scanner/plugins/fingerprint/webidentity/matcher"
)

// Engine coordinates fingerprint evaluation against in-memory caches and active probes.
type Engine struct {
	fingerprints []*CompiledFingerprint
}

// New creates an Engine with the provided compiled fingerprints.
func New(fps []*CompiledFingerprint) *Engine {
	active := make([]*CompiledFingerprint, 0, len(fps))
	for _, fp := range fps {
		if fp != nil && !fp.raw.GetConfig().GetDisabled() {
			active = append(active, fp)
		}
	}
	return &Engine{fingerprints: active}
}

// Fingerprints returns the active compiled fingerprints in this engine.
func (e *Engine) Fingerprints() []*CompiledFingerprint {
	return e.fingerprints
}

func stepURLCacheKey(software, stepName, method, targetURL string) string {
	return software + "|url|" + stepName + "|" + method + "|" + targetURL
}

func stepRootCacheKey(software, root, stepName string) string {
	return software + "|root|" + root + "|" + stepName
}

// Run executes Pass 1 (passive cache evaluation) and Pass 2 (targeted active queries).
func (e *Engine) Run(ctx context.Context, c *cache.Cache, baseURL string) ([]*IdentificationResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	stepCache := make(map[string]*matcher.MatchResult)
	states := e.evaluatePass1WithCache(ctx, c, baseURL, stepCache)

	if err := e.evaluatePass2WithCache(ctx, c, baseURL, states, stepCache); err != nil {
		return nil, err
	}

	keptStates := mergeIdentifiedStates(states)
	return toIdentificationResults(keptStates), nil
}

// evaluatePass1 inspects all responses currently in the cache and matches workflows passively.
func (e *Engine) evaluatePass1(ctx context.Context, c *cache.Cache, baseURL string) map[string]*matchState {
	return e.evaluatePass1WithCache(ctx, c, strings.TrimRight(baseURL, "/"), make(map[string]*matcher.MatchResult))
}

func (e *Engine) evaluatePass1WithCache(ctx context.Context, c *cache.Cache, baseURL string, stepCache map[string]*matcher.MatchResult) map[string]*matchState {
	states := make(map[string]*matchState)
	if c == nil {
		return states
	}

	for _, entry := range c.All() {
		ep := entryPath(entry)
		eu := entryURL(entry, baseURL, ep)
		if baseURL != "" && eu != baseURL && !strings.HasPrefix(eu, baseURL+"/") {
			continue
		}
		entryMethod := entry.Method
		if entryMethod == "" {
			entryMethod = http.MethodGet
		}

		for _, fp := range e.fingerprints {
			for _, wf := range fp.workflows {
				root, versions, matched, step0Matched := e.evaluateWorkflowPass1(ctx, c, baseURL, fp.software, wf, entry, entryMethod, ep, eu, stepCache)
				if matched {
					getOrCreateState(states, fp.software, root).recordSuccess(versions, workflowStepNames(wf))
				} else if step0Matched {
					getOrCreateState(states, fp.software, root)
				}
			}
		}
	}

	return states
}

func (e *Engine) evaluateWorkflowPass1(ctx context.Context, c *cache.Cache, baseURL, software string, wf *matcher.CompiledWorkflow, entry *cache.CachedResponse, entryMethod, ep, eu string, stepCache map[string]*matcher.MatchResult) (string, []string, bool, bool) {
	steps := wf.Steps()
	if len(steps) == 0 {
		return "", nil, false, false
	}
	step0 := steps[0]
	if methodToString(step0.Raw().GetMethod()) != entryMethod {
		return "", nil, false, false
	}
	root, matchesPattern := testStep0Pattern(ep, step0)
	if !matchesPattern {
		return "", nil, false, false
	}

	res0, err := e.evalStep(ctx, software, step0, entryMethod, eu, entry.Response(), entry.Body, stepCache)
	if err != nil || !res0.Matched {
		return "", nil, false, false
	}
	if stepCache != nil {
		stepCache[stepRootCacheKey(software, root, step0.Name())] = res0
	}

	versions, ok := e.evaluateRemainingCachedSteps(ctx, c, baseURL, root, software, steps[1:], res0, stepCache)
	if !ok {
		return root, nil, false, true
	}
	return root, versions, true, true
}

func (e *Engine) evaluateRemainingCachedSteps(ctx context.Context, c *cache.Cache, baseURL, root, software string, steps []*matcher.CompiledStep, res0 *matcher.MatchResult, stepCache map[string]*matcher.MatchResult) ([]string, bool) {
	versions := slices.Clone(res0.Versions)
	vars := make(map[string]string)
	maps.Copy(vars, res0.ExtractedVars)

	for _, step := range steps {
		methodStr, targetURL, ok := resolveStepTarget(baseURL, root, step, vars)
		if !ok {
			return nil, false
		}
		cachedStepResp, found := c.Get(methodStr, targetURL)
		if !found {
			return nil, false
		}
		resI, err := e.evalStep(ctx, software, step, methodStr, targetURL, cachedStepResp.Response(), cachedStepResp.Body, stepCache)
		if err != nil || !resI.Matched {
			return nil, false
		}
		maps.Copy(vars, resI.ExtractedVars)
		versions = append(versions, resI.Versions...)
	}
	return versions, true
}

func (e *Engine) evaluatePass2WithCache(ctx context.Context, c *cache.Cache, baseURL string, states map[string]*matchState, stepCache map[string]*matcher.MatchResult) error {
	if c == nil {
		return nil
	}

	for _, fp := range e.fingerprints {
		roots := e.candidateRootsForFingerprint(fp, states)

		for _, root := range roots {
			s := getOrCreateState(states, fp.software, root)

			// If already identified and has a version, early exit!
			if s.isComplete() {
				continue
			}

			for _, wf := range fp.workflows {
				if err := ctx.Err(); err != nil {
					return err
				}

				if s.isComplete() {
					break
				}
				// If already identified without a version, only run workflows that extract versions.
				if s.isIdentified() && !hasVersionExtractors(wf) {
					continue
				}

				wfPassed, versions, err := e.executeActiveWorkflow(ctx, c, baseURL, root, fp.software, wf, stepCache)
				if err != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						return ctxErr
					}
					continue
				}
				if wfPassed {
					s.recordSuccess(versions, workflowStepNames(wf))
				}
			}
		}
	}

	return nil
}

func (e *Engine) executeActiveWorkflow(ctx context.Context, c *cache.Cache, baseURL, root, software string, wf *matcher.CompiledWorkflow, stepCache map[string]*matcher.MatchResult) (bool, []string, error) {
	vars := make(map[string]string)
	var allVersions []string

	for i, step := range wf.Steps() {
		if i == 0 && stepCache != nil {
			if res0, ok := stepCache[stepRootCacheKey(software, root, step.Name())]; ok && res0.Matched {
				maps.Copy(vars, res0.ExtractedVars)
				allVersions = append(allVersions, res0.Versions...)
				continue
			}
		}

		methodStr, targetURL, ok := resolveStepTarget(baseURL, root, step, vars)
		if !ok {
			return false, nil, nil
		}

		res, err := e.fetchAndEvalStep(ctx, c, software, step, methodStr, targetURL, stepCache)
		if err != nil {
			return false, nil, err
		}
		if !res.Matched {
			return false, nil, nil
		}

		maps.Copy(vars, res.ExtractedVars)
		allVersions = append(allVersions, res.Versions...)
	}

	return true, allVersions, nil
}

func (e *Engine) fetchAndEvalStep(ctx context.Context, c *cache.Cache, software string, step *matcher.CompiledStep, method, targetURL string, stepCache map[string]*matcher.MatchResult) (*matcher.MatchResult, error) {
	if stepCache != nil {
		if cachedRes, ok := stepCache[stepURLCacheKey(software, step.Name(), method, targetURL)]; ok {
			return cachedRes, nil
		}
	}

	req, err := newStepRequest(ctx, step, method, targetURL)
	if err != nil {
		return nil, err
	}

	respEntry, err := c.Fetch(ctx, req)
	if err != nil {
		return nil, err
	}

	return e.evalStep(ctx, software, step, method, targetURL, respEntry.Response(), respEntry.Body, stepCache)
}

func newStepRequest(ctx context.Context, step *matcher.CompiledStep, method, targetURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(step.Raw().GetData()))
	if err != nil {
		return nil, err
	}
	for _, h := range step.Raw().GetHeaders() {
		req.Header.Add(h.GetName(), h.GetValue())
	}
	return req, nil
}

func resolveStepTarget(baseURL, root string, step *matcher.CompiledStep, vars map[string]string) (string, string, bool) {
	stepPath := step.Raw().GetPath()
	if stepPath == "" {
		stepPath = step.Raw().GetPathSuffix()
	}
	if stepPath == "" {
		return "", "", false
	}
	stepPath = matcher.SubstituteVariables(stepPath, vars)
	if !strings.HasPrefix(stepPath, "/") {
		stepPath = "/" + stepPath
	}
	targetURL := baseURL + root + stepPath
	return methodToString(step.Raw().GetMethod()), targetURL, true
}

func (e *Engine) evalStep(ctx context.Context, software string, step *matcher.CompiledStep, method, targetURL string, resp *http.Response, body []byte, stepCache map[string]*matcher.MatchResult) (*matcher.MatchResult, error) {
	key := stepURLCacheKey(software, step.Name(), method, targetURL)
	if stepCache != nil {
		if cached, ok := stepCache[key]; ok {
			return cached, nil
		}
	}

	res, err := step.Match(resp, body)
	if err != nil {
		log.DebugContextf(ctx, log.DebugLevelRequest, "definition %q step %q failed on %s: %v", software, step.Name(), targetURL, err)
		return nil, err
	}

	if res.Matched {
		log.DebugContextf(ctx, log.DebugLevelRequest, "definition %q step %q matched on %s", software, step.Name(), targetURL)
	} else {
		log.DebugContextf(ctx, log.DebugLevelRequest, "definition %q step %q did not match on %s", software, step.Name(), targetURL)
	}

	if stepCache != nil {
		stepCache[key] = res
	}
	return res, nil
}

func (e *Engine) candidateRootsForFingerprint(fp *CompiledFingerprint, states map[string]*matchState) []string {
	var roots []string
	seen := make(map[string]bool)

	for _, s := range states {
		if s.software == fp.software && !seen[s.rootPath] {
			roots = append(roots, s.rootPath)
			seen[s.rootPath] = true
		}
	}
	slices.Sort(roots)
	// Always include top-level root "" if not yet considered.
	if !seen[""] {
		roots = append(roots, "")
	}
	return roots
}

func testStep0Pattern(ep string, step0 *matcher.CompiledStep) (string, bool) {
	if suffix := step0.Raw().GetPathSuffix(); suffix != "" {
		return matcher.InferRootFromSuffix(ep, suffix)
	}
	if re := step0.PathRegexp(); re != nil {
		return matcher.InferRootFromRegexp(ep, re)
	}
	if p := step0.Raw().GetPath(); p != "" {
		if ep == p {
			return "", true
		}
		if strings.HasSuffix(ep, p) {
			return matcher.InferRootFromSuffix(ep, p)
		}
	}
	return "", false
}

func entryPath(entry *cache.CachedResponse) string {
	if entry.URL != nil && entry.URL.Path != "" {
		return entry.URL.Path
	}
	return "/"
}

func entryURL(entry *cache.CachedResponse, baseURL, path string) string {
	if entry.URL != nil && entry.URL.String() != "" {
		return entry.URL.String()
	}
	return baseURL + path
}

func workflowStepNames(wf *matcher.CompiledWorkflow) []string {
	steps := wf.Steps()
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name())
	}
	return names
}

func hasVersionExtractors(wf *matcher.CompiledWorkflow) bool {
	for _, step := range wf.Steps() {
		if len(step.Matcher().Raw().GetVersionExtractors()) > 0 {
			return true
		}
	}
	return false
}

func methodToString(m fpb.HttpMethod) string {
	switch m {
	case fpb.HttpMethod_POST, fpb.HttpMethod_HEAD, fpb.HttpMethod_OPTIONS, fpb.HttpMethod_PUT, fpb.HttpMethod_DELETE:
		return m.String()
	default:
		return http.MethodGet
	}
}
