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
	"io/fs"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/goonami-scanner/common/testfakes/fakellmagent"
	"github.com/google/goonami-scanner/core/config"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"google.golang.org/protobuf/proto"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

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
			cfg := makeDumpTestConfig(t, 2)

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

func TestRunWithFeedbackLoop_DumpsChainOfThoughts(t *testing.T) {
	cfg := makeDumpTestConfig(t, 1)

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

func TestRunWithFeedbackLoop_DumpsSessionOnExpiredContext(t *testing.T) {
	testCases := []struct {
		name          string
		callerTimeout time.Duration
		wantErr       error
	}{
		{
			name:          "when_caller_deadline_expires_during_stalled_turn_dumps_partial_trajectory",
			callerTimeout: 2 * time.Second,
			wantErr:       context.DeadlineExceeded,
		},
		{
			name:    "when_per_turn_timeout_expires_dumps_partial_trajectory",
			wantErr: ErrMaxAttemptsReached,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := makeDumpTestConfig(t, 1)

			synctest.Test(t, func(t *testing.T) {
				unblock := make(chan struct{})
				t.Cleanup(func() { close(unblock) })

				ag := newToolCallingLLMAgent(t, func(_ agent.Context, _ probeToolArgs) (probeToolResult, error) {
					<-unblock
					return probeToolResult{Status: "ok"}, nil
				})

				c := New(cfg, ag)
				c.sessionService = &fakeSessionService{Service: session.InMemoryService()}

				ctx := t.Context()
				if tc.callerTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.callerTimeout)
					defer cancel()
				}

				_, err := c.RunWithFeedbackLoop(ctx, userContent("initial prompt"), nil)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("RunWithFeedbackLoop() error = %v, want %v", err, tc.wantErr)
				}
			})

			dump := readDumpedSession(t, os.DirFS(cfg.ArtifactsDirectory()))
			if dump == nil {
				t.Fatalf("readDumpedSession(%q) = nil, want session dump after timeout", cfg.ArtifactsDirectory())
			}

			wantParts := []*genai.Part{
				{Text: "initial prompt"},
				{
					FunctionCall: &genai.FunctionCall{
						ID:   "call-probe",
						Name: "probe",
						Args: map[string]any{"target": "http://example.test"},
					},
				},
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
		})
	}
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

func makeDumpTestConfig(t *testing.T, maxAttempts int32) *config.Config {
	t.Helper()
	cfg := makeTestConfig(maxAttempts, 0)
	cfg.ClientsConfig().GetLlm().SetDumpTrajectories(true)
	if err := cfg.CreateDirectories(t.TempDir()); err != nil {
		t.Fatalf("CreateDirectories() failed: %v", err)
	}
	return cfg
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
