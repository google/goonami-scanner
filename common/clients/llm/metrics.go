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

package llm

import (
	"context"

	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/genai"
)

func (c *Client) addUsage(ctx context.Context, usage *genai.GenerateContentResponseUsageMetadata, modelVersion string) {
	if usage == nil {
		return
	}
	c.totalTokenCount += usage.TotalTokenCount
	c.cachedContentTokenCount += usage.CachedContentTokenCount
	recordTokens(ctx, usage, modelVersion)
}

// recordTokens attributes token consumption to the model that served the
// response.
//
// The breakdown mirrors what the backend reports: the total is the sum of the
// prompt, the generated candidates, the tool results fed back in and the
// thinking tokens. Each count is recorded only when present, so a model that
// does not think, or a request that uses no tools, simply has no series rather
// than a series pinned at zero.
func recordTokens(ctx context.Context, usage *genai.GenerateContentResponseUsageMetadata, model string) {
	label := metrics.LLMModel(model)

	counts := []struct {
		metric *metrics.Counter
		value  int32
	}{
		{metrics.LLMTokens, usage.TotalTokenCount},
		{metrics.LLMInputTokens, usage.PromptTokenCount},
		{metrics.LLMCachedTokens, usage.CachedContentTokenCount},
		{metrics.LLMOutputTokens, usage.CandidatesTokenCount},
		{metrics.LLMThoughtTokens, usage.ThoughtsTokenCount},
		{metrics.LLMToolInputTokens, usage.ToolUsePromptTokenCount},
	}

	for _, count := range counts {
		if count.value > 0 {
			count.metric.Add(ctx, int64(count.value), label)
		}
	}
}
