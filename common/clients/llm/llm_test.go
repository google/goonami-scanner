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
	"fmt"
	"iter"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"google.golang.org/protobuf/proto"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestNew(t *testing.T) {
	llmConfig := lccpb.LlmClientConfig_builder{
		MaxAttempts: proto.Int32(5),
	}.Build()
	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: llmConfig,
		}.Build(),
	}.Build())

	ag := fakellmagent.New(nil, nil)
	client := New(cfg, ag)
	if client == nil {
		t.Fatalf("New() returned a nil client")
	}

	// Verify that the config was merged correctly with defaults.
	wantConfig := DefaultConfig()
	proto.Merge(wantConfig, llmConfig)

	if !proto.Equal(client.config, wantConfig) {
		t.Errorf("New() did not merge config correctly: got %v, want %v", client.config, wantConfig)
	}

	// Double check specific fields to be explicitly sure.
	if client.config.GetMaxAttempts() != 5 {
		t.Errorf("client.config.MaxAttempts = %d, want 5", client.config.GetMaxAttempts())
	}
	if client.config.GetTimeoutPerRequestSeconds() != DefaultConfig().GetTimeoutPerRequestSeconds() {
		t.Errorf("client.config.TimeoutPerRequestSeconds = %d, want default %d", client.config.GetTimeoutPerRequestSeconds(), DefaultConfig().GetTimeoutPerRequestSeconds())
	}

	if client.ag != ag {
		t.Errorf("New() did not set agent correctly: got %v, want %v", client.ag, ag)
	}
	if client.appName != DefaultAppName {
		t.Errorf("New() did not set appName correctly: got %v, want %v", client.appName, DefaultAppName)
	}
	if client.userID != DefaultUserID {
		t.Errorf("New() did not set userID correctly: got %v, want %v", client.userID, DefaultUserID)
	}
	if client.sessionService == nil {
		t.Errorf("New() did not set sessionService")
	}
}

func TestRunWithFeedbackLoop(t *testing.T) {
	testConfig := lccpb.LlmClientConfig_builder{
		TimeoutPerRequestSeconds: proto.Int32(1),
		RetryDelaySeconds:        proto.Int32(0),
		MaxAttempts:              proto.Int32(1),
	}.Build()
	defaultContent := userContent("hello world")

	testCases := []struct {
		name          string
		llmConfig     *lccpb.LlmClientConfig
		agent         *fakellmagent.FakeAgent
		content       *genai.Content
		verifier      AgentResultVerifier
		cancelContext bool
		tamper        func(*Client)
		assert        func(*testing.T, *Client)
		want          string
		wantErr       error
	}{
		{
			name:    "when_agent_returns_verified_result_it_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello world"),
			content: defaultContent,
			verifier: func(ctx context.Context, result string) error {
				if result != "hello world" {
					return fmt.Errorf("unexpected agent result: %q", result)
				}
				return nil
			},
			want: "hello world",
		},
		{
			name:    "when_verification_fails_max_attempts_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("invalid"),
			content: defaultContent,
			verifier: func(ctx context.Context, result string) error {
				if result == "invalid" {
					return errors.New("schema validation failed")
				}
				return nil
			},
			wantErr: ErrMaxAttemptsReached,
		},
		{
			name:    "when_agent_returns_error_several_times_max_attempts_error_is_returned",
			agent:   fakellmagent.NewWithError(errors.New("agent error")),
			content: defaultContent,
			wantErr: ErrMaxAttemptsReached,
		},
		{
			name: "when_verification_fails_repeatedly_max_attempts_error_is_returned",
			llmConfig: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(1),
				RetryDelaySeconds:        proto.Int32(0),
				MaxAttempts:              proto.Int32(2),
			}.Build(),
			agent:    fakellmagent.NewWithSimpleAnswer("bad"),
			content:  defaultContent,
			verifier: func(ctx context.Context, result string) error { return errors.New("verifier error") },
			wantErr:  ErrMaxAttemptsReached,
		},
		{
			name:          "when_context_is_cancelled_error_is_returned",
			agent:         fakellmagent.New(nil, nil),
			content:       defaultContent,
			cancelContext: true,
			wantErr:       context.Canceled,
		},
		{
			name:    "when_session_service_is_nil_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello"),
			content: defaultContent,
			wantErr: ErrMaxAttemptsReached,
			tamper:  func(c *Client) { c.sessionService = nil },
		},
		{
			name:    "when_session_service_create_fails_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello"),
			content: defaultContent,
			wantErr: ErrMaxAttemptsReached,
			tamper: func(c *Client) {
				c.sessionService = &fakeSessionService{}
			},
		},
		{
			name: "when_response_contains_thought_parts_they_are_filtered",
			agent: fakellmagent.New([]*session.Event{{
				LLMResponse: model.LLMResponse{
					Content: &genai.Content{
						Parts: []*genai.Part{
							{Text: "Thinking process...", Thought: true},
							{Text: "Final answer"},
						},
					},
				},
			}}, []error{nil}),
			content: defaultContent,
			want:    "Final answer",
		},
		{
			name:    "when_runner_creation_fails_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello"),
			content: defaultContent,
			wantErr: ErrMaxAttemptsReached,
			tamper:  func(c *Client) { c.ag = nil },
		},
		{
			name: "when_event_has_usage_metadata_and_nil_content_usage_is_recorded",
			agent: fakellmagent.New([]*session.Event{
				{
					LLMResponse: model.LLMResponse{
						UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
							TotalTokenCount:         42,
							CachedContentTokenCount: 10,
						},
					},
				},
				{
					LLMResponse: model.LLMResponse{
						Content: &genai.Content{
							Parts: []*genai.Part{{Text: "done"}},
						},
					},
				},
			}, []error{nil, nil}),
			content: defaultContent,
			want:    "done",
			assert: func(t *testing.T, c *Client) {
				if c.totalTokenCount != 42 || c.cachedContentTokenCount != 10 {
					t.Errorf("token usage = (total: %d, cached: %d), want (42, 10)", c.totalTokenCount, c.cachedContentTokenCount)
				}
			},
		},
		{
			name:    "when_content_is_nil_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello"),
			content: nil,
			wantErr: ErrContentRequired,
		},
		{
			name:    "when_content_role_is_missing_error_is_returned",
			agent:   fakellmagent.NewWithSimpleAnswer("hello"),
			content: &genai.Content{Parts: []*genai.Part{{Text: "hello world"}}},
			wantErr: ErrContentRequired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			llmConfig := tc.llmConfig
			if llmConfig == nil {
				llmConfig = testConfig
			}
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: llmConfig,
				}.Build(),
			}.Build())

			c := New(cfg, tc.agent)
			if tc.tamper != nil {
				tc.tamper(c)
			}

			ctx := t.Context()
			if tc.cancelContext {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			got, err := c.RunWithFeedbackLoop(ctx, tc.content, tc.verifier)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("RunWithFeedbackLoop() error = %v, wantErr %v", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("RunWithFeedbackLoop() returned diff (-want +got):\n%s", diff)
			}

			if tc.assert != nil {
				tc.assert(t, c)
			}
		})
	}

	t.Run("when_verification_fails_conversational_refinement_preserves_session", func(t *testing.T) {
		var sessions, prompts []string

		ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
			sessions = append(sessions, ic.Session().ID())
			prompts = append(prompts, ic.UserContent().Parts[0].Text)
			if len(sessions) > 1 {
				return textEvent("attempt2-fixed"), nil
			}
			return textEvent("attempt1"), nil
		})

		c := New(makeTestConfig(3, 0), ag)
		content := userContent("initial prompt")
		verifier := func(ctx context.Context, result string) error {
			if result == "attempt1" {
				return errors.New("invalid output format")
			}
			return nil
		}

		got, err := c.RunWithFeedbackLoop(t.Context(), content, verifier)
		if err != nil {
			t.Fatalf("RunWithFeedbackLoop() error = %v", err)
		}
		if got != "attempt2-fixed" {
			t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, "attempt2-fixed")
		}
		if len(sessions) != 2 || sessions[0] != sessions[1] {
			t.Errorf("session IDs = %v, want both turns to share the same session", sessions)
		}
		if !strings.Contains(prompts[1], "invalid output format") {
			t.Errorf("turn 2 feedback missing diagnostic error: %v", prompts)
		}
	})

	t.Run("when_hard_failure_occurs_session_is_reset_and_prompt_restored", func(t *testing.T) {
		var sessions, prompts []string

		ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
			sessions = append(sessions, ic.Session().ID())
			prompts = append(prompts, ic.UserContent().Parts[0].Text)
			switch len(sessions) {
			case 1:
				return textEvent("attempt1"), nil
			case 2:
				return nil, errors.New("hard agent crash")
			default:
				return textEvent("recovered"), nil
			}
		})

		c := New(makeTestConfig(3, 0), ag)
		content := userContent("initial prompt")
		verifier := func(ctx context.Context, result string) error {
			if result == "attempt1" {
				return errors.New("invalid format")
			}
			return nil
		}

		got, err := c.RunWithFeedbackLoop(t.Context(), content, verifier)
		if err != nil {
			t.Fatalf("RunWithFeedbackLoop() error = %v", err)
		}
		if got != "recovered" {
			t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, "recovered")
		}
		if len(sessions) != 3 {
			t.Fatalf("invocations = %d, want 3", len(sessions))
		}
		if sessions[0] != sessions[1] {
			t.Errorf("turn 2 session = %q, want same session as turn 1 %q", sessions[1], sessions[0])
		}
		if sessions[2] == sessions[1] {
			t.Errorf("turn 3 session = %q, want new session after crash", sessions[2])
		}
		if prompts[2] != "initial prompt" {
			t.Errorf("recovered turn did not restore initial prompt: %q", prompts[2])
		}
	})

	t.Run("when_attempt_fails_transiently_backoff_is_applied_between_attempts", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var timestamps []time.Time
			ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
				timestamps = append(timestamps, time.Now())
				if len(timestamps) == 1 {
					return nil, errors.New("transient error")
				}
				return textEvent("success"), nil
			})

			retryDelay := 10 * time.Second
			c := New(makeTestConfig(2, int32(retryDelay.Seconds())), ag)
			got, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if err != nil {
				t.Fatalf("RunWithFeedbackLoop() error = %v", err)
			}
			if got != "success" {
				t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, "success")
			}
			if len(timestamps) != 2 {
				t.Fatalf("agent invoked %d times, want 2", len(timestamps))
			}
			if delay := timestamps[1].Sub(timestamps[0]); delay != retryDelay {
				t.Errorf("delay between attempts = %v, want %v", delay, retryDelay)
			}
		})
	})

	t.Run("when_context_is_canceled_during_agent_run_returns_context_canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
				cancel()
				return nil, errors.New("agent failed")
			})

			c := New(makeTestConfig(3, 10), ag)
			_, err := c.RunWithFeedbackLoop(ctx, userContent("prompt"), nil)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want context.Canceled", err)
			}
		})
	})

	t.Run("when_context_is_canceled_during_backoff_returns_context_canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(1*time.Second, cancel)
			ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
				return nil, errors.New("hard error")
			})

			c := New(makeTestConfig(3, 10), ag)
			_, err := c.RunWithFeedbackLoop(ctx, userContent("prompt"), nil)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want context.Canceled", err)
			}
		})
	})

	t.Run("when_custom_user_id_is_configured_it_is_passed_to_session", func(t *testing.T) {
		var capturedUserID string
		ag := testAgent(t, func(ic agent.InvocationContext) (*session.Event, error) {
			capturedUserID = ic.Session().UserID()
			return textEvent("ok"), nil
		})

		c := New(makeTestConfig(1, 0), ag)
		c.userID = "custom-user-123"
		if _, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil); err != nil {
			t.Fatalf("RunWithFeedbackLoop() error = %v", err)
		}
		if capturedUserID != "custom-user-123" {
			t.Errorf("capturedUserID = %q, want %q", capturedUserID, "custom-user-123")
		}
	})
}

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
					textEvent("done"),
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
					textEvent("done"),
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
					textEvent("done"),
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
					textEvent("done"),
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
					textEvent("done"),
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
					textEvent("done"),
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
					textEvent("bad"),
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			collector := installCollector(t)

			c := New(makeTestConfig(tc.maxAttempts, 0), tc.agent)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), tc.verifier)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RunWithFeedbackLoop() error = %v, wantErr %v", err, tc.wantErr)
			}

			for name, want := range tc.wantTokens {
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

type fakeSessionService struct {
	session.Service
}

func (f *fakeSessionService) Create(ctx context.Context, req *session.CreateRequest) (*session.CreateResponse, error) {
	return nil, errors.New("create error")
}

func TestGetModel(t *testing.T) {
	testCases := []struct {
		name      string
		llmConfig *lccpb.LlmClientConfig
		tier      ModelTier
		want      string
	}{
		{
			name:      "when_tier_is_lite_and_config_is_empty_returns_default",
			llmConfig: nil,
			tier:      ModelTierLite,
			want:      "gemini-3.5-flash-lite",
		},
		{
			name:      "when_tier_is_fast_and_config_is_empty_returns_default",
			llmConfig: nil,
			tier:      ModelTierFast,
			want:      "gemini-3.6-flash",
		},
		{
			name:      "when_tier_is_pro_and_config_is_empty_returns_default",
			llmConfig: nil,
			tier:      ModelTierPro,
			want:      "gemini-3.1-pro-preview",
		},
		{
			name:      "when_tier_is_unknown_and_config_is_empty_returns_lite_default",
			llmConfig: nil,
			tier:      ModelTier(999),
			want:      "gemini-3.5-flash-lite",
		},
		{
			name: "when_tier_is_lite_and_config_has_model_returns_model",
			llmConfig: lccpb.LlmClientConfig_builder{
				LiteModel: proto.String("custom-lite"),
			}.Build(),
			tier: ModelTierLite,
			want: "custom-lite",
		},
		{
			name: "when_tier_is_fast_and_config_has_model_returns_model",
			llmConfig: lccpb.LlmClientConfig_builder{
				FastModel: proto.String("custom-fast"),
			}.Build(),
			tier: ModelTierFast,
			want: "custom-fast",
		},
		{
			name: "when_tier_is_pro_and_config_has_model_returns_model",
			llmConfig: lccpb.LlmClientConfig_builder{
				ProModel: proto.String("custom-pro"),
			}.Build(),
			tier: ModelTierPro,
			want: "custom-pro",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgBuilder := cpb.Config_builder{}
			if tc.llmConfig != nil {
				cfgBuilder.Clients = cpb.ClientsConfig_builder{
					Llm: tc.llmConfig,
				}.Build()
			}
			cfg := config.FromProto(cfgBuilder.Build())

			got := GetModel(cfg, tc.tier)
			if got != tc.want {
				t.Errorf("GetModel() = %v, want %v", got, tc.want)
			}
		})
	}
}

func userContent(text string) *genai.Content {
	return &genai.Content{
		Role:  "user",
		Parts: []*genai.Part{{Text: text}},
	}
}

func makeTestConfig(maxAttempts, retryDelaySeconds int32) *config.Config {
	return config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(5),
				RetryDelaySeconds:        proto.Int32(retryDelaySeconds),
				MaxAttempts:              proto.Int32(maxAttempts),
			}.Build(),
		}.Build(),
	}.Build())
}

func testAgent(t *testing.T, run func(ic agent.InvocationContext) (*session.Event, error)) agent.Agent {
	t.Helper()
	ag, err := agent.New(agent.Config{
		Name: "test-agent",
		Run: func(ic agent.InvocationContext) iter.Seq2[*session.Event, error] {
			return func(yield func(*session.Event, error) bool) {
				ev, err := run(ic)
				yield(ev, err)
			}
		},
	})
	if err != nil {
		t.Fatalf("agent.New() error = %v", err)
	}
	return ag
}

func textEvent(text string) *session.Event {
	return &session.Event{
		LLMResponse: model.LLMResponse{
			Content: &genai.Content{Parts: []*genai.Part{{Text: text}}},
		},
	}
}
