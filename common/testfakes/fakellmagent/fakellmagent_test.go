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
	"errors"
	"iter"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
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

func TestFakeAgent(t *testing.T) {
	err := errors.New("fake error")
	answer := "fake answer"
	event := &session.Event{
		LLMResponse: model.LLMResponse{
			Content: &genai.Content{
				Parts: []*genai.Part{
					&genai.Part{
						Text: answer,
					},
				},
			},
		},
	}

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
