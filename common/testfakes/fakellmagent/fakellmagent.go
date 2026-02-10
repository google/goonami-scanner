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
	"iter"

	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// FakeAgent is a fake implementation of agent.Agent for testing.
type FakeAgent struct {
	agent.Agent
	events    []*session.Event
	errors    []error
	callCount int
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
	events := []*session.Event{
		&session.Event{
			LLMResponse: model.LLMResponse{
				Content: &genai.Content{
					Parts: []*genai.Part{
						&genai.Part{
							Text: answer,
						},
					},
				},
			},
		},
	}
	errors := []error{nil}

	return New(events, errors)
}

// NewWithError creates a new fake agent that returns a single error.
func NewWithError(err error) *FakeAgent {
	events := []*session.Event{nil}
	errors := []error{err}
	return New(events, errors)
}

// Run returns a channel of agent events and errors based on the configured behaviors.
func (f *FakeAgent) Run(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
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
