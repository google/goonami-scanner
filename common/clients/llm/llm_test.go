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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		llmConfig  *lccpb.LlmClientConfig
		wantConfig *lccpb.LlmClientConfig
	}{
		{
			name: "when_llm_config_is_set_it_overrides_the_defaults",
			llmConfig: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(5),
			}.Build(),
			wantConfig: lccpb.LlmClientConfig_builder{
				MaxAttempts: proto.Int32(5),
			}.Build(),
		},
		{
			name:       "when_llm_config_is_absent_the_defaults_are_used",
			wantConfig: &lccpb.LlmClientConfig{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: tc.llmConfig,
				}.Build(),
			}.Build())

			ag := fakellmagent.New(nil, nil)
			client := New(cfg, ag)
			if client == nil {
				t.Fatalf("New() returned a nil client")
			}

			if diff := cmp.Diff(tc.wantConfig, client.config, protocmp.Transform()); diff != "" {
				t.Errorf("New() config returned unexpected diff (-want +got):\n%s", diff)
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
			if client.sessionService != defaultSessionService {
				t.Errorf("New() sessionService = %v, want the default in-memory session service", client.sessionService)
			}
		})
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
			name: "when_verifier_aborts_no_further_attempt_is_made",
			llmConfig: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(1),
				RetryDelaySeconds:        proto.Int32(0),
				MaxAttempts:              proto.Int32(2),
			}.Build(),
			agent:   fakellmagent.NewWithSimpleAnswer("answer"),
			content: defaultContent,
			verifier: func() AgentResultVerifier {
				calls := 0
				return func(ctx context.Context, result string) error {
					calls++
					if calls == 1 {
						return fmt.Errorf("%w: target is rate limiting", ErrAbort)
					}
					return nil
				}
			}(),
			wantErr: ErrAbort,
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

		ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
			sessions = append(sessions, ic.Session().ID())
			prompts = append(prompts, ic.UserContent().Parts[0].Text)
			if len(sessions) > 1 {
				return fakellmagent.TextEvent("attempt2-fixed"), nil
			}
			return fakellmagent.TextEvent("attempt1"), nil
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

		ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
			sessions = append(sessions, ic.Session().ID())
			prompts = append(prompts, ic.UserContent().Parts[0].Text)
			switch len(sessions) {
			case 1:
				return fakellmagent.TextEvent("attempt1"), nil
			case 2:
				return nil, errors.New("hard agent crash")
			default:
				return fakellmagent.TextEvent("recovered"), nil
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
			ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
				timestamps = append(timestamps, time.Now())
				if len(timestamps) == 1 {
					return nil, errors.New("transient error")
				}
				return fakellmagent.TextEvent("success"), nil
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
			ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
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
			start := time.Now()
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(1*time.Second, cancel)
			ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
				return nil, errors.New("hard error")
			})

			c := New(makeTestConfig(3, 10), ag)
			_, err := c.RunWithFeedbackLoop(ctx, userContent("prompt"), nil)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want context.Canceled", err)
			}
			if elapsed := time.Since(start); elapsed != 1*time.Second {
				t.Errorf("elapsed = %v, want 1s", elapsed)
			}
		})
	})

	t.Run("when_overall_feedback_loop_timeout_expires_stops_retrying_and_returns_deadline_exceeded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var invocations int
			ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
				invocations++
				time.Sleep(100 * time.Second)
				return nil, errors.New("stalled attempt failed")
			})

			c := New(makeTestConfig(3, 10), ag)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want context.DeadlineExceeded", err)
			}
			if invocations != 1 {
				t.Errorf("invocations = %d, want 1", invocations)
			}
		})
	})

	t.Run("when_turn_context_expires_during_event_stream_stops_iteration_immediately", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var stepsExecuted int
			ag := fakellmagent.NewWithSeq(func(ic agent.InvocationContext) iter.Seq2[*session.Event, error] {
				return func(yield func(*session.Event, error) bool) {
					stepsExecuted++
					// Simulate a tool call that stalls past the 5s per-turn timeout and
					// still yields a function-response event instead of returning a Go error.
					time.Sleep(6 * time.Second)
					if !yield(fakellmagent.TextEvent("tool-response-event"), nil) {
						return
					}
					// If runTurn did not break out of the event loop on ctx.Err(),
					// ADK would proceed to the next step and call the LLM again.
					stepsExecuted++
					yield(fakellmagent.TextEvent("final-answer"), nil)
				}
			})

			c := New(makeTestConfig(1, 0), ag)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if !errors.Is(err, ErrMaxAttemptsReached) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want %v", err, ErrMaxAttemptsReached)
			}
			if stepsExecuted != 1 {
				t.Errorf("stepsExecuted = %d, want 1 (should stop before next step)", stepsExecuted)
			}
		})
	})

	t.Run("when_turn_context_expires_on_partial_event_token_usage_is_recorded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			collector := installCollector(t)

			ag := fakellmagent.NewWithSeq(func(ic agent.InvocationContext) iter.Seq2[*session.Event, error] {
				return func(yield func(*session.Event, error) bool) {
					time.Sleep(6 * time.Second)
					event := &session.Event{
						LLMResponse: model.LLMResponse{
							ModelVersion: "gemini-3.6-flash",
							Partial:      true,
							UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
								TotalTokenCount:         50,
								CachedContentTokenCount: 15,
							},
						},
					}
					yield(event, nil)
				}
			})

			c := New(makeTestConfig(1, 0), ag)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if !errors.Is(err, ErrMaxAttemptsReached) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want %v", err, ErrMaxAttemptsReached)
			}
			if c.totalTokenCount != 50 || c.cachedContentTokenCount != 15 {
				t.Errorf("token usage = (total: %d, cached: %d), want (50, 15)", c.totalTokenCount, c.cachedContentTokenCount)
			}

			label := metrics.LLMModel("gemini-3.6-flash")
			if got := collector.Value(t.Context(), metrics.LLMTokens, label); got != 50 {
				t.Errorf("%s[%s] = %d, want 50", metrics.LLMTokens.Name(), "gemini-3.6-flash", got)
			}
			if got := collector.Value(t.Context(), metrics.LLMCachedTokens, label); got != 15 {
				t.Errorf("%s[%s] = %d, want 15", metrics.LLMCachedTokens.Name(), "gemini-3.6-flash", got)
			}
		})
	})

	t.Run("when_custom_user_id_is_configured_it_is_passed_to_session", func(t *testing.T) {
		var capturedUserID string
		ag := fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
			capturedUserID = ic.Session().UserID()
			return fakellmagent.TextEvent("ok"), nil
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
	createErr    error
	getErr       error
	getCalls     int
	failGetAfter int
}

func (f *fakeSessionService) Create(ctx context.Context, req *session.CreateRequest) (*session.CreateResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.Service != nil {
		return f.Service.Create(ctx, req)
	}
	return nil, errors.New("create error")
}

func (f *fakeSessionService) Get(ctx context.Context, req *session.GetRequest) (*session.GetResponse, error) {
	f.getCalls++
	if f.failGetAfter > 0 && f.getCalls > f.failGetAfter && f.getErr != nil {
		return nil, f.getErr
	}
	if f.failGetAfter == 0 && f.getErr != nil {
		return nil, f.getErr
	}
	if f.Service != nil {
		return f.Service.Get(ctx, req)
	}
	return nil, errors.New("get error")
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

func TestTimeoutPerRequest(t *testing.T) {
	testCases := []struct {
		name      string
		llmConfig *lccpb.LlmClientConfig
		want      time.Duration
	}{
		{
			name:      "when_config_is_empty_returns_default",
			llmConfig: nil,
			want:      240 * time.Second,
		},
		{
			name: "when_llm_config_has_timeout_returns_configured_timeout",
			llmConfig: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(90),
			}.Build(),
			want: 90 * time.Second,
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

			if got := TimeoutPerRequest(cfg); got != tc.want {
				t.Errorf("TimeoutPerRequest() = %v, want %v", got, tc.want)
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

func TestRunWithFeedbackLoop_DumpsSession(t *testing.T) {
	rejectFirst := func(ctx context.Context, result string) error {
		if result == "first response" {
			return errors.New("need correction")
		}
		return nil
	}

	testCases := []struct {
		name       string
		agent      agent.Agent
		verifier   AgentResultVerifier
		wantResult string
		wantEvents []string
	}{
		{
			name:       "when_single_turn_succeeds_dumps_session_json_in_module_directory",
			agent:      fakellmagent.NewWithSimpleAnswer("final response"),
			wantResult: "final response",
			wantEvents: []string{"initial prompt", "final response"},
		},
		{
			name:       "when_multiple_turns_in_same_session_updates_session_dump",
			agent:      newSequentialAgent("first response", "second response"),
			verifier:   rejectFirst,
			wantResult: "second response",
			wantEvents: []string{
				"initial prompt",
				"first response",
				feedbackContent(errors.New("need correction")).Parts[0].Text,
				"second response",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: lccpb.LlmClientConfig_builder{
						TimeoutPerRequestSeconds: proto.Int32(5),
						RetryDelaySeconds:        proto.Int32(0),
						MaxAttempts:              proto.Int32(2),
						DumpTrajectories:         proto.Bool(true),
					}.Build(),
				}.Build(),
			}.Build())
			if err := cfg.CreateDirectories(t.TempDir()); err != nil {
				t.Fatalf("CreateDirectories() failed: %v", err)
			}

			c := New(cfg, tc.agent)
			got, err := c.RunWithFeedbackLoop(t.Context(), userContent("initial prompt"), tc.verifier)
			if err != nil {
				t.Fatalf("RunWithFeedbackLoop() failed: %v", err)
			}
			if got != tc.wantResult {
				t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, tc.wantResult)
			}

			dump := readDumpedSession(t, os.DirFS(cfg.ArtifactsDirectory()))
			if dump == nil {
				t.Fatalf("expected session dump file in %q, found none", cfg.ArtifactsDirectory())
			}
			if dump.ID == "" {
				t.Errorf("dump.ID is empty")
			}
			if dump.AppName != DefaultAppName {
				t.Errorf("dump.AppName = %q, want %q", dump.AppName, DefaultAppName)
			}
			if dump.UserID != DefaultUserID {
				t.Errorf("dump.UserID = %q, want %q", dump.UserID, DefaultUserID)
			}

			var gotEvents []string
			for _, ev := range dump.Events {
				if ev.Content != nil && len(ev.Content.Parts) > 0 {
					gotEvents = append(gotEvents, ev.Content.Parts[0].Text)
				}
			}
			if diff := cmp.Diff(tc.wantEvents, gotEvents); diff != "" {
				t.Errorf("dumped session events diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRunWithFeedbackLoop_DoesNotDumpSession(t *testing.T) {
	testCases := []struct {
		name             string
		dumpTrajectories bool
		initArtifacts    bool
		unwritableDir    bool
		sessionService   session.Service
	}{
		{
			name:             "when_dump_trajectories_is_disabled_no_file_is_written",
			dumpTrajectories: false,
			initArtifacts:    true,
		},
		{
			name:             "when_artifacts_directory_is_not_initialized_run_still_succeeds",
			dumpTrajectories: true,
			initArtifacts:    false,
		},
		{
			name:             "when_session_get_fails_run_still_succeeds",
			dumpTrajectories: true,
			initArtifacts:    true,
			sessionService: &fakeSessionService{
				Service:      session.InMemoryService(),
				getErr:       errors.New("forced get error"),
				failGetAfter: 1,
			},
		},
		{
			name:             "when_artifacts_directory_is_unwritable_run_still_succeeds",
			dumpTrajectories: true,
			initArtifacts:    true,
			unwritableDir:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: lccpb.LlmClientConfig_builder{
						TimeoutPerRequestSeconds: proto.Int32(5),
						RetryDelaySeconds:        proto.Int32(0),
						MaxAttempts:              proto.Int32(1),
						DumpTrajectories:         proto.Bool(tc.dumpTrajectories),
					}.Build(),
				}.Build(),
			}.Build())

			if tc.initArtifacts {
				if err := cfg.CreateDirectories(t.TempDir()); err != nil {
					t.Fatalf("CreateDirectories() failed: %v", err)
				}
				if tc.unwritableDir {
					moduleDir, err := cfg.ArtifactsForModule(llmMetricsModule)
					if err != nil {
						t.Fatalf("ArtifactsForModule() failed: %v", err)
					}
					if err := os.Chmod(moduleDir, 0500); err != nil {
						t.Fatalf("os.Chmod() failed: %v", err)
					}
					t.Cleanup(func() { os.Chmod(moduleDir, 0700) })
				}
			}

			c := New(cfg, fakellmagent.NewWithSimpleAnswer("final response"))
			if tc.sessionService != nil {
				c.sessionService = tc.sessionService
			}

			got, err := c.RunWithFeedbackLoop(t.Context(), userContent("initial prompt"), nil)
			if err != nil {
				t.Fatalf("RunWithFeedbackLoop() failed: %v", err)
			}
			if got != "final response" {
				t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, "final response")
			}

			if tc.initArtifacts {
				if dump := readDumpedSession(t, os.DirFS(cfg.ArtifactsDirectory())); dump != nil {
					t.Errorf("readDumpedSession() = %+v, want nil", dump)
				}
			}
		})
	}
}

func newSequentialAgent(responses ...string) agent.Agent {
	turn := 0
	return fakellmagent.NewWithFunc(func(ic agent.InvocationContext) (*session.Event, error) {
		resp := responses[turn]
		turn++
		return fakellmagent.TextEvent(resp), nil
	})
}

func readDumpedSession(t *testing.T, fsys fs.FS) *sessionDump {
	t.Helper()
	matches, err := fs.Glob(fsys, "clients/llm/session_*.json")
	if err != nil {
		t.Fatalf("fs.Glob() failed: %v", err)
	}
	if len(matches) == 0 {
		return nil
	}
	if len(matches) > 1 {
		t.Fatalf("found %d session dump files (%v), want at most 1", len(matches), matches)
	}

	data, err := fs.ReadFile(fsys, matches[0])
	if err != nil {
		t.Fatalf("fs.ReadFile(%q) failed: %v", matches[0], err)
	}

	var dump sessionDump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}
	return &dump
}

func TestIncludeThoughts(t *testing.T) {
	testCases := []struct {
		name       string
		req        *model.LLMRequest
		wantConfig *genai.GenerateContentConfig
	}{
		{
			name: "when_request_is_nil_does_not_panic",
			req:  nil,
		},
		{
			name: "when_config_is_nil_initializes_config_and_enables_include_thoughts",
			req:  &model.LLMRequest{},
			wantConfig: &genai.GenerateContentConfig{
				ThinkingConfig: &genai.ThinkingConfig{
					IncludeThoughts: true,
				},
			},
		},
		{
			name: "when_thinking_config_is_nil_initializes_thinking_config_and_enables_include_thoughts",
			req: &model.LLMRequest{
				Config: &genai.GenerateContentConfig{
					Temperature: proto.Float32(0.7),
				},
			},
			wantConfig: &genai.GenerateContentConfig{
				Temperature: proto.Float32(0.7),
				ThinkingConfig: &genai.ThinkingConfig{
					IncludeThoughts: true,
				},
			},
		},
		{
			name: "when_thinking_config_exists_sets_include_thoughts_preserving_existing_fields",
			req: &model.LLMRequest{
				Config: &genai.GenerateContentConfig{
					ThinkingConfig: &genai.ThinkingConfig{
						ThinkingBudget: proto.Int32(100),
					},
				},
			},
			wantConfig: &genai.GenerateContentConfig{
				ThinkingConfig: &genai.ThinkingConfig{
					ThinkingBudget:  proto.Int32(100),
					IncludeThoughts: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := includeThoughts(nil, tc.req)
			if err != nil {
				t.Fatalf("includeThoughts() error = %v, want nil", err)
			}
			if resp != nil {
				t.Errorf("includeThoughts() resp = %+v, want nil", resp)
			}
			if tc.req != nil {
				if diff := cmp.Diff(tc.wantConfig, tc.req.Config); diff != "" {
					t.Errorf("includeThoughts() Config diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestRunWithFeedbackLoop_DumpsChainOfThoughts(t *testing.T) {
	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(5),
				RetryDelaySeconds:        proto.Int32(0),
				MaxAttempts:              proto.Int32(1),
				DumpTrajectories:         proto.Bool(true),
			}.Build(),
		}.Build(),
	}.Build())
	if err := cfg.CreateDirectories(t.TempDir()); err != nil {
		t.Fatalf("CreateDirectories() failed: %v", err)
	}

	fakeLLM := fakellmagent.NewModel(
		[]*model.LLMResponse{
			{
				Content: &genai.Content{
					Role: "model",
					Parts: []*genai.Part{
						{Text: "thinking step by step", Thought: true},
						{Text: "final response"},
					},
				},
			},
		},
		[]error{nil},
	)

	ag, err := llmagent.New(llmagent.Config{
		Name:  "test-thought-agent",
		Model: fakeLLM,
	})
	if err != nil {
		t.Fatalf("llmagent.New() failed: %v", err)
	}

	c := New(cfg, ag)
	got, err := c.RunWithFeedbackLoop(t.Context(), userContent("initial prompt"), nil)
	if err != nil {
		t.Fatalf("RunWithFeedbackLoop() failed: %v", err)
	}
	if got != "final response" {
		t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, "final response")
	}

	if len(fakeLLM.Requests()) != 1 {
		t.Fatalf("fakeLLM.Requests() length = %d, want 1", len(fakeLLM.Requests()))
	}
	reqCfg := fakeLLM.Requests()[0].Config
	if reqCfg == nil || reqCfg.ThinkingConfig == nil || !reqCfg.ThinkingConfig.IncludeThoughts {
		t.Errorf("fakeLLM.Requests()[0].Config = %+v, want ThinkingConfig.IncludeThoughts = true", reqCfg)
	}

	dump := readDumpedSession(t, os.DirFS(cfg.ArtifactsDirectory()))
	if dump == nil {
		t.Fatalf("expected session dump file in %q, found none", cfg.ArtifactsDirectory())
	}

	wantParts := []*genai.Part{
		{Text: "initial prompt"},
		{Text: "thinking step by step", Thought: true},
		{Text: "final response"},
	}
	var gotParts []*genai.Part
	for _, ev := range dump.Events {
		if ev.Content != nil {
			gotParts = append(gotParts, ev.Content.Parts...)
		}
	}
	if diff := cmp.Diff(wantParts, gotParts); diff != "" {
		t.Errorf("dumped session parts diff (-want +got):\n%s", diff)
	}
}
