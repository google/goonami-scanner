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

// Package fakellmagent provides a fake implementation of the ADK agent for testing.
package fakellmagent

import (
	"context"
	"iter"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
)

// RunFn is the type of function that produces a single event or error for a fake agent invocation.
type RunFn func(ctx agent.InvocationContext) (*session.Event, error)

// RunSeqFn is the type of function that overrides the Run() sequence of the fake agent.
type RunSeqFn func(ctx agent.InvocationContext) iter.Seq2[*session.Event, error]

// FakeAgent is a fake implementation of agent.Agent for testing.
type FakeAgent struct {
	agent.Agent
	events   []*session.Event
	errors   []error
	runSeq   RunSeqFn
	onPrompt func(string)
}

// TextEvent creates a session.Event containing a single text part.
func TextEvent(text string) *session.Event {
	return &session.Event{
		LLMResponse: model.LLMResponse{
			Content: &genai.Content{
				Parts: []*genai.Part{
					{
						Text: text,
					},
				},
			},
		},
	}
}

// New creates a new fake agent.
func New(events []*session.Event, errors []error) *FakeAgent {
	if len(events) != len(errors) {
		panic("events and errors must be the same length")
	}

	ag, err := agent.New(agent.Config{
		Name:        "fake-agent",
		Description: "fake-agent",
	})

	if err != nil {
		panic(err)
	}
	return &FakeAgent{
		Agent:  ag,
		events: events,
		errors: errors,
	}
}

// NewWithSimpleAnswer creates a new fake agent that returns a single event with the given answer.
func NewWithSimpleAnswer(answer string) *FakeAgent {
	events := []*session.Event{TextEvent(answer)}
	errors := []error{nil}

	return New(events, errors)
}

// NewWithError creates a new fake agent that returns a single error.
func NewWithError(err error) *FakeAgent {
	events := []*session.Event{nil}
	errors := []error{err}
	return New(events, errors)
}

// NewWithFunc creates a new fake agent that invokes fn on each Run() call and yields its result.
func NewWithFunc(fn RunFn) *FakeAgent {
	return NewWithSeq(func(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
		return func(yield func(*session.Event, error) bool) {
			ev, err := fn(ctx)
			yield(ev, err)
		}
	})
}

// NewWithSeq creates a new fake agent that delegates Run() to fn.
func NewWithSeq(fn RunSeqFn) *FakeAgent {
	f := New(nil, nil)
	f.runSeq = fn
	return f
}

// WithOnPrompt registers a callback that receives the first user prompt text on each Run() call.
func (f *FakeAgent) WithOnPrompt(fn func(string)) *FakeAgent {
	f.onPrompt = fn
	return f
}

// Run returns a sequence of agent events and errors based on the configured behaviors.
func (f *FakeAgent) Run(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
	if f.onPrompt != nil && ctx != nil && ctx.UserContent() != nil && len(ctx.UserContent().Parts) > 0 {
		f.onPrompt(ctx.UserContent().Parts[0].Text)
	}
	if f.runSeq != nil {
		return f.runSeq(ctx)
	}
	return func(yield func(*session.Event, error) bool) {
		for i := 0; i < len(f.events); i++ {
			if !yield(f.events[i], f.errors[i]) {
				return
			}
		}
	}
}

// Name of the agent.
func (f *FakeAgent) Name() string {
	return "fake-agent"
}

// Description of the agent.
func (f *FakeAgent) Description() string {
	return "fake-agent"
}

// SubAgents returns a list of sub-agents.
func (f *FakeAgent) SubAgents() []agent.Agent {
	return nil
}

// FakeContext is a fake implementation of agent.Context backed by a standard context.Context.
type FakeContext struct {
	agent.Context
	ctx context.Context
}

// NewContext creates a new FakeContext wrapping the given context.Context.
func NewContext(ctx context.Context) *FakeContext {
	return &FakeContext{ctx: ctx}
}

// Deadline returns the time when work done on behalf of this context should be canceled.
func (f *FakeContext) Deadline() (time.Time, bool) { return f.ctx.Deadline() }

// Done returns a channel that's closed when work done on behalf of this context should be canceled.
func (f *FakeContext) Done() <-chan struct{} { return f.ctx.Done() }

// Err returns a non-nil error value after Done is closed.
func (f *FakeContext) Err() error { return f.ctx.Err() }

// Value returns the value associated with this context for key.
func (f *FakeContext) Value(key any) any { return f.ctx.Value(key) }

// FakeModel is a fake implementation of model.LLM for testing.
type FakeModel struct {
	responses []*model.LLMResponse
	errors    []error
	requests  []*model.LLMRequest
}

// NewModel creates a new FakeModel that yields the given responses and errors.
func NewModel(responses []*model.LLMResponse, errors []error) *FakeModel {
	if len(responses) != len(errors) {
		panic("responses and errors must be the same length")
	}
	return &FakeModel{
		responses: responses,
		errors:    errors,
	}
}

// Name returns the name of the fake model.
func (m *FakeModel) Name() string {
	return "fake-model"
}

// Requests returns the list of LLM requests captured during GenerateContent calls.
func (m *FakeModel) Requests() []*model.LLMRequest {
	return m.requests
}

// GenerateContent records the incoming request and yields the configured responses and errors.
func (m *FakeModel) GenerateContent(_ context.Context, req *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	m.requests = append(m.requests, req)
	return func(yield func(*model.LLMResponse, error) bool) {
		for i := range len(m.responses) {
			if !yield(m.responses[i], m.errors[i]) {
				return
			}
		}
	}
}
