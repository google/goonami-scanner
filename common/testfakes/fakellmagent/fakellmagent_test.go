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

package fakellmagent

import (
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"google.golang.org/protobuf/testing/protocmp"
)

type result struct {
	Event *session.Event
	Err   error
}

func collectResults(seq iter.Seq2[*session.Event, error]) []result {
	var results []result
	next, stop := iter.Pull2(seq)
	defer stop()
	for {
		event, err, ok := next()
		if !ok {
			break
		}
		results = append(results, result{Event: event, Err: err})
	}
	return results
}

type fakeInvocationContext struct {
	agent.InvocationContext
	content *genai.Content
}

func (f *fakeInvocationContext) UserContent() *genai.Content {
	return f.content
}

func TestFakeAgent(t *testing.T) {
	err := errors.New("fake error")
	answer := "fake answer"
	event := TextEvent(answer)

	testCases := []struct {
		name string
		ag   *FakeAgent
		want []result
	}{
		{
			name: "when_simple_answer_returns_answer",
			ag:   NewWithSimpleAnswer(answer),
			want: []result{{Event: event, Err: nil}},
		},
		{
			name: "when_error_returns_error",
			ag:   NewWithError(err),
			want: []result{{Event: nil, Err: err}},
		},
		{
			name: "when_new_returns_events_and_errors",
			ag:   New([]*session.Event{event, nil}, []error{nil, err}),
			want: []result{{Event: event, Err: nil}, {Event: nil, Err: err}},
		},
		{
			name: "when_new_with_func_returns_func_result",
			ag: NewWithFunc(func(ctx agent.InvocationContext) (*session.Event, error) {
				return event, nil
			}),
			want: []result{{Event: event, Err: nil}},
		},
		{
			name: "when_new_with_seq_returns_seq_results",
			ag: NewWithSeq(func(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
				return func(yield func(*session.Event, error) bool) {
					yield(event, nil)
				}
			}),
			want: []result{{Event: event, Err: nil}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := collectResults(tc.ag.Run(nil))

			if len(got) != len(tc.want) {
				t.Errorf("Run() returned %d results, want %d", len(got), len(tc.want))
			}

			for i := range len(got) {
				gotErr := got[i].Err
				wantErr := tc.want[i].Err

				if !errors.Is(gotErr, wantErr) {
					t.Errorf("Run() returned unexpected error: got %v, want %v", gotErr, wantErr)
				}

				gotEvent := got[i].Event
				wantEvent := tc.want[i].Event

				if wantEvent != nil {
					if diff := cmp.Diff(wantEvent, gotEvent, protocmp.Transform()); diff != "" {
						t.Errorf("Run() returned unexpected diff (-want +got):\n%s", diff)
					}
				} else if gotEvent != nil {
					t.Errorf("Run() returned unexpected event: %v", gotEvent)
				}
			}
		})
	}
}

func TestFakeAgentWithOnPrompt(t *testing.T) {
	tests := []struct {
		name       string
		ctx        agent.InvocationContext
		wantPrompt string
	}{
		{
			name: "when_user_content_has_text_captures_prompt",
			ctx: &fakeInvocationContext{
				content: &genai.Content{
					Parts: []*genai.Part{{Text: "hello prompt"}},
				},
			},
			wantPrompt: "hello prompt",
		},
		{
			name:       "when_invocation_context_is_nil_does_not_call_callback",
			ctx:        nil,
			wantPrompt: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPrompt string
			ag := NewWithSimpleAnswer("ok").WithOnPrompt(func(prompt string) {
				gotPrompt = prompt
			})
			_ = collectResults(ag.Run(tc.ctx))
			if gotPrompt != tc.wantPrompt {
				t.Errorf("captured prompt = %q, want %q", gotPrompt, tc.wantPrompt)
			}
		})
	}
}

func TestFakeAgentInfo(t *testing.T) {
	ag := NewWithSimpleAnswer("test")
	if got, want := ag.Name(), "fake-agent"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := ag.Description(), "fake-agent"; got != want {
		t.Errorf("Description() = %q, want %q", got, want)
	}
	if ag.SubAgents() != nil {
		t.Errorf("SubAgents() got %v, want nil", ag.SubAgents())
	}
}

func TestFakeContext(t *testing.T) {
	type ctxKey string
	tests := []struct {
		name         string
		setupCtx     func(t *testing.T) context.Context
		wantDeadline bool
		wantErr      error
		wantVal      any
	}{
		{
			name: "when_context_is_canceled_delegates_done_and_err",
			setupCtx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			wantErr: context.Canceled,
		},
		{
			name: "when_context_has_deadline_and_value_delegates_both",
			setupCtx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				t.Cleanup(cancel)
				return context.WithValue(ctx, ctxKey("k"), "v")
			},
			wantDeadline: true,
			wantVal:      "v",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fc := NewContext(tc.setupCtx(t))
			_, hasDeadline := fc.Deadline()
			if hasDeadline != tc.wantDeadline {
				t.Errorf("Deadline() ok = %v, want %v", hasDeadline, tc.wantDeadline)
			}
			if !errors.Is(fc.Err(), tc.wantErr) {
				t.Errorf("Err() = %v, want %v", fc.Err(), tc.wantErr)
			}
			if tc.wantErr != nil {
				select {
				case <-fc.Done():
				default:
					t.Errorf("Done() channel not closed when Err() = %v", tc.wantErr)
				}
			}
			if got := fc.Value(ctxKey("k")); got != tc.wantVal {
				t.Errorf("Value() = %v, want %v", got, tc.wantVal)
			}
		})
	}
}
