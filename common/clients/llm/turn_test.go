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
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/genai"
	"google.golang.org/protobuf/proto"
)

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

func TestRunWithFeedbackLoop_EnforcesContextDeadlines(t *testing.T) {
	testCases := []struct {
		name              string
		maxAttempts       int32
		retryDelaySecs    int32
		callerTimeout     time.Duration
		cancelAfter       time.Duration
		stallUntilAttempt int32
		wantResult        string
		wantErr           error
		wantElapsed       time.Duration
		wantToolCalls     int32
		wantTotalTokens   int32
	}{
		{
			name:              "when_llm_agent_tool_ignores_context_cancellation_enforces_per_turn_timeout_and_retries",
			maxAttempts:       3,
			retryDelaySecs:    10,
			stallUntilAttempt: 3,
			wantErr:           ErrMaxAttemptsReached,
			wantElapsed:       35 * time.Second,
			wantToolCalls:     3,
			wantTotalTokens:   75,
		},
		{
			name:              "when_caller_deadline_expires_during_blocked_llm_agent_tool_returns_deadline_exceeded_immediately",
			maxAttempts:       3,
			retryDelaySecs:    10,
			callerTimeout:     2 * time.Second,
			stallUntilAttempt: 3,
			wantErr:           context.DeadlineExceeded,
			wantElapsed:       2 * time.Second,
			wantToolCalls:     1,
			wantTotalTokens:   25,
		},
		{
			name:              "when_caller_cancels_context_on_single_attempt_returns_context_canceled_instead_of_max_attempts",
			maxAttempts:       1,
			cancelAfter:       1 * time.Second,
			stallUntilAttempt: 1,
			wantErr:           context.Canceled,
			wantElapsed:       1 * time.Second,
			wantToolCalls:     1,
			wantTotalTokens:   25,
		},
		{
			name:              "when_llm_agent_stalls_on_first_attempt_and_succeeds_on_retry_returns_result",
			maxAttempts:       2,
			retryDelaySecs:    10,
			stallUntilAttempt: 1,
			wantResult:        "recovered answer",
			wantElapsed:       15 * time.Second,
			wantToolCalls:     2,
			wantTotalTokens:   50,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				unblock := make(chan struct{})
				t.Cleanup(func() { close(unblock) })

				var toolCalls atomic.Int32
				ag := newToolCallingLLMAgent(t, func(_ agent.Context, _ probeToolArgs) (probeToolResult, error) {
					call := toolCalls.Add(1)
					if call <= tc.stallUntilAttempt {
						// Intentionally ignore agent.Context cancellation to simulate a
						// non-cooperative tool or hung socket read.
						<-unblock
					}
					return probeToolResult{Status: "ok"}, nil
				})

				ctx := t.Context()
				if tc.callerTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.callerTimeout)
					defer cancel()
				}
				if tc.cancelAfter > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					defer cancel()
					time.AfterFunc(tc.cancelAfter, cancel)
				}

				start := time.Now()
				c := New(makeTestConfig(tc.maxAttempts, tc.retryDelaySecs), ag)
				got, err := c.RunWithFeedbackLoop(ctx, userContent("probe target"), nil)
				elapsed := time.Since(start)

				if !errors.Is(err, tc.wantErr) {
					t.Errorf("RunWithFeedbackLoop() error = %v, wantErr %v", err, tc.wantErr)
				}
				if got != tc.wantResult {
					t.Errorf("RunWithFeedbackLoop() = %q, want %q", got, tc.wantResult)
				}
				if elapsed != tc.wantElapsed {
					t.Errorf("elapsed = %v, want %v", elapsed, tc.wantElapsed)
				}
				if gotCalls := toolCalls.Load(); gotCalls != tc.wantToolCalls {
					t.Errorf("toolCalls = %d, want %d", gotCalls, tc.wantToolCalls)
				}
				if c.totalTokenCount != tc.wantTotalTokens {
					t.Errorf("totalTokenCount = %d, want %d", c.totalTokenCount, tc.wantTotalTokens)
				}
			})
		})
	}

	t.Run("when_turn_context_expires_during_event_stream_stops_iteration_immediately", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var stepsExecuted atomic.Int32
			unblock := make(chan struct{})
			closeUnblock := sync.OnceFunc(func() { close(unblock) })
			t.Cleanup(closeUnblock)

			ag := fakellmagent.NewWithSeq(func(ic agent.InvocationContext) iter.Seq2[*session.Event, error] {
				return func(yield func(*session.Event, error) bool) {
					stepsExecuted.Add(1)
					// Simulate a tool call that stalls past the 5s per-turn timeout
					// ignoring ic.Done(), and still tries to yield a function-response
					// event once it eventually unblocks.
					<-unblock
					if !yield(fakellmagent.TextEvent("tool-response-event"), nil) {
						return
					}
					// If runTurn did not stop consuming the event stream on timeout,
					// ADK would proceed to the next step and call the LLM again.
					stepsExecuted.Add(1)
					yield(fakellmagent.TextEvent("final-answer"), nil)
				}
			})

			start := time.Now()
			c := New(makeTestConfig(1, 0), ag)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if !errors.Is(err, ErrMaxAttemptsReached) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want %v", err, ErrMaxAttemptsReached)
			}
			if elapsed := time.Since(start); elapsed != 5*time.Second {
				t.Errorf("elapsed = %v, want 5s", elapsed)
			}
			closeUnblock()
			synctest.Wait()
			if got := stepsExecuted.Load(); got != 1 {
				t.Errorf("stepsExecuted = %d, want 1 (should stop before next step)", got)
			}
		})
	})

	t.Run("when_turn_context_expires_on_partial_event_token_usage_is_recorded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			collector := installCollector(t)
			unblock := make(chan struct{})
			t.Cleanup(func() { close(unblock) })

			ag := fakellmagent.NewWithSeq(func(ic agent.InvocationContext) iter.Seq2[*session.Event, error] {
				return func(yield func(*session.Event, error) bool) {
					chunks := []int32{20, 50}
					for _, total := range chunks {
						event := &session.Event{
							LLMResponse: model.LLMResponse{
								ModelVersion: "gemini-3.6-flash",
								Partial:      true,
								UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
									TotalTokenCount:         total,
									CachedContentTokenCount: 15,
								},
							},
						}
						if !yield(event, nil) {
							return
						}
					}
					// Stall past the 5s per-turn timeout without yielding a final non-partial event.
					<-unblock
				}
			})

			start := time.Now()
			c := New(makeTestConfig(1, 0), ag)
			_, err := c.RunWithFeedbackLoop(t.Context(), userContent("prompt"), nil)
			if !errors.Is(err, ErrMaxAttemptsReached) {
				t.Errorf("RunWithFeedbackLoop() error = %v, want %v", err, ErrMaxAttemptsReached)
			}
			if elapsed := time.Since(start); elapsed != 5*time.Second {
				t.Errorf("elapsed = %v, want 5s", elapsed)
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
}

type probeToolArgs struct {
	Target string `json:"target"`
}

type probeToolResult struct {
	Status string `json:"status"`
}

func hasFunctionResponse(contents []*genai.Content) bool {
	for _, content := range contents {
		if content == nil {
			continue
		}
		for _, part := range content.Parts {
			if part != nil && part.FunctionResponse != nil {
				return true
			}
		}
	}
	return false
}

func newToolCallingLLMAgent(t *testing.T, handler functiontool.Func[probeToolArgs, probeToolResult]) agent.Agent {
	t.Helper()

	probeTool, err := functiontool.New(functiontool.Config{
		Name:        "probe",
		Description: "probes a target endpoint",
	}, handler)
	if err != nil {
		t.Fatalf("functiontool.New() failed: %v", err)
	}

	llmModel := fakellmagent.NewModelWithFunc(func(_ context.Context, req *model.LLMRequest) (*model.LLMResponse, error) {
		if hasFunctionResponse(req.Contents) {
			return &model.LLMResponse{
				ModelVersion: "gemini-3.6-flash",
				Content: &genai.Content{
					Role:  "model",
					Parts: []*genai.Part{{Text: "recovered answer"}},
				},
			}, nil
		}
		return &model.LLMResponse{
			ModelVersion: "gemini-3.6-flash",
			Content: &genai.Content{
				Role: "model",
				Parts: []*genai.Part{{
					FunctionCall: &genai.FunctionCall{
						ID:   "call-probe",
						Name: "probe",
						Args: map[string]any{"target": "http://example.test"},
					},
				}},
			},
			UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
				TotalTokenCount: 25,
			},
		}, nil
	})

	ag, err := llmagent.New(llmagent.Config{
		Name:  "test-tool-agent",
		Model: llmModel,
		Tools: []tool.Tool{probeTool},
	})
	if err != nil {
		t.Fatalf("llmagent.New() failed: %v", err)
	}
	return ag
}
