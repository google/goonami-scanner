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
	"errors"
	"strings"
	"testing"

	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
)

func TestRunWithFeedbackLoopRecordsMetrics(t *testing.T) {
	usageEvent := func(name string, usage *genai.GenerateContentResponseUsageMetadata) *session.Event {
		return &session.Event{
			LLMResponse: model.LLMResponse{
				ModelVersion:  name,
				UsageMetadata: usage,
			},
		}
	}
	// partial marks an event as a streaming chunk rather than a finished turn.
	partial := func(event *session.Event) *session.Event {
		event.Partial = true
		return event
	}
	rejectAll := func(ctx context.Context, result string) error { return errors.New("rejected") }

	// tokenCounts is the expected breakdown of llm/tokens for one model.
	type tokenCounts struct {
		total, input, cached, output, thoughts, toolInput int64
	}

	testCases := []struct {
		name        string
		maxAttempts int32
		agent       *fakellmagent.FakeAgent
		verifier    AgentResultVerifier
		wantErr     error
		wantTokens  map[string]tokenCounts
		wantBudget  int64
	}{
		{
			name:        "when_run_succeeds_tokens_are_attributed_to_the_serving_model",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         42,
						CachedContentTokenCount: 10,
					}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil}),
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 42, cached: 10}},
		},
		{
			// The parts satisfy the identity the backend documents:
			// total = prompt + candidates + tool use prompt + thoughts.
			name:        "when_the_backend_reports_every_field_the_whole_breakdown_is_recorded",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						PromptTokenCount:        100,
						CachedContentTokenCount: 60,
						CandidatesTokenCount:    20,
						ThoughtsTokenCount:      30,
						ToolUsePromptTokenCount: 5,
						TotalTokenCount:         155,
					}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil}),
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {
				total: 155, input: 100, cached: 60, output: 20, thoughts: 30, toolInput: 5,
			}},
		},
		{
			name:        "when_an_event_is_partial_its_usage_is_not_counted",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					partial(usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:  11,
						PromptTokenCount: 7,
					})),
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:  11,
						PromptTokenCount: 7,
					}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil, nil}),
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 11, input: 7}},
		},
		{
			name:        "when_a_run_uses_several_models_each_is_attributed_separately",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         30,
						CachedContentTokenCount: 5,
					}),
					usageEvent("gemini-3.1-pro-preview", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount: 100,
					}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil, nil}),
			wantTokens: map[string]tokenCounts{
				"gemini-3.6-flash":       {total: 30, cached: 5},
				"gemini-3.1-pro-preview": {total: 100},
			},
		},
		{
			name:        "when_the_same_model_answers_twice_its_counts_are_summed",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         7,
						CachedContentTokenCount: 1,
					}),
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         8,
						CachedContentTokenCount: 2,
					}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil, nil}),
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 15, cached: 3}},
		},
		{
			name:        "when_the_backend_reports_no_model_tokens_are_attributed_to_unknown",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("", &genai.GenerateContentResponseUsageMetadata{TotalTokenCount: 12}),
					fakellmagent.TextEvent("done"),
				},
				[]error{nil, nil}),
			wantTokens: map[string]tokenCounts{"unknown": {total: 12}},
		},
		{
			name:        "when_usage_metadata_is_absent_no_token_is_recorded",
			maxAttempts: 1,
			agent:       fakellmagent.NewWithSimpleAnswer("done"),
			wantTokens:  map[string]tokenCounts{},
		},
		{
			name:        "when_attempts_are_retried_tokens_of_every_attempt_are_recorded",
			maxAttempts: 2,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         5,
						CachedContentTokenCount: 1,
					}),
					fakellmagent.TextEvent("bad"),
				},
				[]error{nil, nil}),
			verifier:   rejectAll,
			wantErr:    ErrMaxAttemptsReached,
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 10, cached: 2}},
			wantBudget: 1,
		},
		{
			name:        "when_the_run_fails_tokens_spent_before_the_failure_are_recorded",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         9,
						CachedContentTokenCount: 3,
					}),
					nil,
				},
				[]error{nil, errors.New("agent crash")}),
			wantErr:    ErrMaxAttemptsReached,
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 9, cached: 3}},
			wantBudget: 1,
		},
		{
			name:        "when_partial_stream_errors_mid_turn_flushes_latest_partial_token_usage",
			maxAttempts: 1,
			agent: fakellmagent.New(
				[]*session.Event{
					partial(usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         20,
						CachedContentTokenCount: 5,
					})),
					partial(usageEvent("gemini-3.6-flash", &genai.GenerateContentResponseUsageMetadata{
						TotalTokenCount:         45,
						CachedContentTokenCount: 12,
					})),
					nil,
				},
				[]error{nil, nil, errors.New("stream reset")}),
			wantErr:    ErrMaxAttemptsReached,
			wantTokens: map[string]tokenCounts{"gemini-3.6-flash": {total: 45, cached: 12}},
			wantBudget: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := installCollector(t)

			c := New(makeTestConfig(tc.maxAttempts, 0), tc.agent)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), tc.verifier)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RunWithFeedbackLoop() error = %v, wantErr %v", err, tc.wantErr)
			}

			var wantTotal, wantCached int32
			for name, want := range tc.wantTokens {
				wantTotal += int32(want.total)
				wantCached += int32(want.cached)

				label := metrics.LLMModel(name)
				checks := []struct {
					metric *metrics.Counter
					want   int64
				}{
					{metrics.LLMTokens, want.total},
					{metrics.LLMInputTokens, want.input},
					{metrics.LLMCachedTokens, want.cached},
					{metrics.LLMOutputTokens, want.output},
					{metrics.LLMThoughtTokens, want.thoughts},
					{metrics.LLMToolInputTokens, want.toolInput},
				}
				for _, check := range checks {
					if got := collector.Value(t.Context(), check.metric, label); got != check.want {
						t.Errorf("%s[%s] = %d, want %d", check.metric.Name(), name, got, check.want)
					}
				}
			}

			if c.totalTokenCount != wantTotal || c.cachedContentTokenCount != wantCached {
				t.Errorf("client token usage = (total: %d, cached: %d), want (%d, %d)",
					c.totalTokenCount, c.cachedContentTokenCount, wantTotal, wantCached)
			}

			if got := countTokenSeries(collector); got != len(tc.wantTokens) {
				t.Errorf("llm/tokens covers %d models, want %d", got, len(tc.wantTokens))
			}

			if got := collector.Value(t.Context(), metrics.BudgetExhausted, metrics.Module(llmMetricsModule), metrics.LimitName(metrics.LimitMaxAttempts)); got != tc.wantBudget {
				t.Errorf("budget/exhausted = %d, want %d", got, tc.wantBudget)
			}

			stats, ok := collector.Stats(t.Context(), metrics.LLMDuration, metrics.ErrorClass(tc.wantErr))
			if !ok {
				t.Fatalf("llm/duration was not recorded for error class %v", metrics.ErrorClass(tc.wantErr))
			}
			if stats.Count != 1 {
				t.Errorf("llm/duration count = %d, want 1", stats.Count)
			}
		})
	}
}

func TestRunWithFeedbackLoopRecordsMetrics_InvalidContent_NoDurationRecorded(t *testing.T) {
	collector := installCollector(t)

	c := New(makeTestConfig(1, 0), fakellmagent.NewWithSimpleAnswer("done"))
	if _, err := c.RunWithFeedbackLoop(t.Context(), nil, nil); !errors.Is(err, ErrContentRequired) {
		t.Fatalf("RunWithFeedbackLoop() error = %v, want %v", err, ErrContentRequired)
	}

	if got := len(collector.Series()); got != 0 {
		t.Errorf("collected %d series, want none: the run never reached the model", got)
	}
}

// countTokenSeries returns how many distinct models token usage was recorded
// for. Counting the series is what proves no extra model was invented; asserting
// the expected ones alone would not.
func countTokenSeries(collector *metrics.Collector) int {
	models := make(map[string]bool)
	for _, series := range collector.Series() {
		// The whole llm/tokens family, so a child added to the catalog is covered
		// here without this helper having to be updated.
		if !strings.HasPrefix(series.Metric.Name(), metrics.LLMTokens.Name()) {
			continue
		}
		for _, label := range series.Labels {
			if label.Key == metrics.LabelModel {
				models[label.Value] = true
			}
		}
	}
	return len(models)
}

// installCollector installs a metrics collector for the duration of the test and
// restores the previous recorder afterwards.
func installCollector(t *testing.T) *metrics.Collector {
	t.Helper()
	collector := metrics.NewCollector()
	metrics.SetRecorder(collector)
	t.Cleanup(func() { metrics.SetRecorder(nil) })
	return collector
}
