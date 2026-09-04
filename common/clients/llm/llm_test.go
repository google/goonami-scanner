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

type fakeSessionService struct {
	session.Service
}

func (f *fakeSessionService) Create(ctx context.Context, req *session.CreateRequest) (*session.CreateResponse, error) {
	return nil, errors.New("create error")
}

func TestRun(t *testing.T) {
	testConfig := makeTestConfig(1, 0)
	defaultContent := userContent("hello world")

	t.Run("when_agent_returns_verified_result_it_is_returned", func(t *testing.T) {
		ag := fakellmagent.NewWithSimpleAnswer("good")
		c := New(testConfig, ag)
		var verifierCalled bool
		got, err := c.Run(t.Context(), defaultContent, func(ctx context.Context, res string) error {
			verifierCalled = true
			if res != "good" {
				t.Errorf("verifier received result %q, want %q", res, "good")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if got != "good" {
			t.Errorf("Run() = %q, want %q", got, "good")
		}
		if !verifierCalled {
			t.Errorf("Run() did not invoke the provided verifier")
		}
	})

	t.Run("when_verification_fails_error_is_returned", func(t *testing.T) {
		ag := fakellmagent.NewWithSimpleAnswer("bad")
		c := New(testConfig, ag)
		_, err := c.Run(t.Context(), defaultContent, func(ctx context.Context, res string) error {
			return errors.New("invalid format")
		})
		if !errors.Is(err, ErrMaxAttemptsReached) {
			t.Errorf("Run() error = %v, want %v", err, ErrMaxAttemptsReached)
		}
	})
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
