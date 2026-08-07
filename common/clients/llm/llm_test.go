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

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/adk/session"
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

func TestRun(t *testing.T) {
	testConfig := lccpb.LlmClientConfig_builder{
		TimeoutPerRequestSeconds: proto.Int32(1),
		RetryDelaySeconds:        proto.Int32(0),
		MaxAttempts:              proto.Int32(1),
	}.Build()
	defaultContent := &genai.Content{
		Role:  "user",
		Parts: []*genai.Part{&genai.Part{Text: "hello world"}},
	}

	testCases := []struct {
		name          string
		llmConfig     *lccpb.LlmClientConfig
		agent         *fakellmagent.FakeAgent
		content       *genai.Content
		verifier      AgentResultVerifier
		cancelContext bool
		tamper        func(*Client)
		want          string
		wantErr       error
	}{
		{
			name:      "when_agent_returns_verified_result_it_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithSimpleAnswer("hello world"),
			content:   defaultContent,
			verifier:  func(ctx context.Context, result string) error { return nil },
			want:      "hello world",
		},
		{
			name:      "when_agent_returns_error_several_times_max_attempts_error_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithError(errors.New("agent error")),
			content:   defaultContent,
			verifier:  func(ctx context.Context, result string) error { return nil },
			wantErr:   ErrMaxAttemptsReached,
		},
		{
			name:      "when_verification_fails_several_times_max_attempts_error_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithSimpleAnswer("bad"),
			content:   defaultContent,
			verifier: func(ctx context.Context, result string) error {
				return errors.New("verifier error")
			},
			wantErr: ErrMaxAttemptsReached,
		},
		{
			name:          "when_context_is_cancelled_error_is_returned",
			llmConfig:     testConfig,
			agent:         fakellmagent.New(nil, nil),
			content:       defaultContent,
			verifier:      func(ctx context.Context, result string) error { return nil },
			cancelContext: true,
			wantErr:       context.Canceled,
		},
		{
			name: "when_max_attempts_is_reached_error_is_returned",
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
			name:      "when_error_is_too_long_it_is_truncated",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithError(errors.New(strings.Repeat("a", 201))),
			content:   defaultContent,
			verifier:  func(ctx context.Context, result string) error { return nil },
			wantErr:   ErrMaxAttemptsReached,
		},
		{
			name:      "when_session_service_fails_error_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithSimpleAnswer("hello"),
			content:   defaultContent,
			verifier:  func(ctx context.Context, result string) error { return nil },
			wantErr:   ErrMaxAttemptsReached,
			tamper:    func(c *Client) { c.sessionService = nil },
		},
		{
			name: "when_verification_fails_once_then_succeeds_result_is_returned",
			llmConfig: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(1),
				RetryDelaySeconds:        proto.Int32(0),
				MaxAttempts:              proto.Int32(2),
			}.Build(),
			agent:   fakellmagent.NewWithSimpleAnswer("good"),
			content: defaultContent,
			verifier: func() AgentResultVerifier {
				var calls int
				return func(ctx context.Context, result string) error {
					calls++
					if calls == 1 {
						return errors.New("verifier error")
					}
					return nil
				}
			}(),
			want: "good",
		},
		{
			name:      "when_content_is_nil_error_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithSimpleAnswer("hello"),
			content:   nil,
			verifier:  func(ctx context.Context, result string) error { return nil },
			wantErr:   ErrContentRequired,
		},
		{
			name:      "when_content_role_is_missing_error_is_returned",
			llmConfig: testConfig,
			agent:     fakellmagent.NewWithSimpleAnswer("hello"),
			content:   &genai.Content{Parts: []*genai.Part{&genai.Part{Text: "hello world"}}},
			verifier:  func(ctx context.Context, result string) error { return nil },
			wantErr:   ErrContentRequired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.FromProto(cpb.Config_builder{
				Clients: cpb.ClientsConfig_builder{
					Llm: tc.llmConfig,
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

			got, err := c.Run(ctx, tc.content, tc.verifier)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Run() error = %v, wantErr %v", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Run() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

type fakeSessionService struct {
	session.Service
}

func (f *fakeSessionService) Create(ctx context.Context, req *session.CreateRequest) (*session.CreateResponse, error) {
	return nil, errors.New("create error")
}

func TestRun_SessionCreateError(t *testing.T) {
	oldSess := defaultSessionService
	defaultSessionService = &fakeSessionService{session.InMemoryService()}
	defer func() {
		defaultSessionService = oldSess
	}()

	cfg := config.FromProto(cpb.Config_builder{
		Clients: cpb.ClientsConfig_builder{
			Llm: lccpb.LlmClientConfig_builder{
				TimeoutPerRequestSeconds: proto.Int32(1),
				RetryDelaySeconds:        proto.Int32(0),
				MaxAttempts:              proto.Int32(1),
			}.Build(),
		}.Build(),
	}.Build())
	ag := fakellmagent.NewWithSimpleAnswer("hello")
	content := &genai.Content{
		Role:  "user",
		Parts: []*genai.Part{&genai.Part{Text: "hello world"}},
	}
	c := New(cfg, ag)
	_, err := c.Run(t.Context(), content, func(ctx context.Context, result string) error { return nil })
	if !errors.Is(err, ErrMaxAttemptsReached) {
		t.Errorf("Run() error = %v, wantErr %v", err, ErrMaxAttemptsReached)
	}
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
