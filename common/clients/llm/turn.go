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
	"fmt"
	"iter"
	"strings"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/plugin"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
)

type runnerItem struct {
	event *session.Event
	err   error
}

// runTurn executes a single network turn with the model through the ADK runner.
// It creates the session if absent, applies the per-request timeout, consumes
// the runner event stream, tracks token consumption, and filters thought parts.
func (c *Client) runTurn(ctx context.Context, sessionID string, content *genai.Content) (string, string, error) {
	if sessionID == "" {
		id, err := c.createSession(ctx)
		if err != nil {
			return "", "", err
		}
		sessionID = id
	}
	defer c.dumpSession(ctx, sessionID)

	r, err := c.newRunner()
	if err != nil {
		return "", "", err
	}

	timeout := time.Duration(c.config.GetTimeoutPerRequestSeconds()) * time.Second
	turnCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := c.consumeEvents(ctx, turnCtx, r.Run(turnCtx, c.userID, sessionID, content, agent.RunConfig{}))
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrAgentRun, err)
	}
	return sessionID, resp, nil
}

func (c *Client) newRunner() (*runner.Runner, error) {
	p, _ := plugin.New(plugin.Config{
		Name:                "thoughts",
		BeforeModelCallback: includeThoughts,
	})
	r, err := runner.New(runner.Config{
		Agent:          c.ag,
		SessionService: c.sessionService,
		AppName:        c.appName,
		PluginConfig: runner.PluginConfig{
			Plugins: []*plugin.Plugin{p},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunnerCreation, err)
	}
	return r, nil
}

// includeThoughts configures Gemini thinking config to include the model's
// chain of thoughts in the response, allowing reasoning to be dumped to session
// events.
func includeThoughts(_ agent.Context, req *model.LLMRequest) (*model.LLMResponse, error) {
	if req == nil {
		return nil, nil
	}
	if req.Config == nil {
		req.Config = &genai.GenerateContentConfig{}
	}
	if req.Config.ThinkingConfig == nil {
		req.Config.ThinkingConfig = &genai.ThinkingConfig{}
	}
	req.Config.ThinkingConfig.IncludeThoughts = true
	return nil, nil
}

func (c *Client) consumeEvents(ctx context.Context, turnCtx context.Context, events iter.Seq2[*session.Event, error]) (string, error) {
	itemCh := forwardEvents(turnCtx, events)

	var (
		response    strings.Builder
		lastPartial *session.Event
	)
	defer func() {
		if lastPartial != nil {
			c.addUsage(ctx, lastPartial.UsageMetadata, lastPartial.ModelVersion)
		}
	}()

	for {
		select {
		case <-turnCtx.Done():
			return "", turnCtx.Err()
		case item, ok := <-itemCh:
			if !ok {
				if err := turnCtx.Err(); err != nil {
					return "", err
				}
				return response.String(), nil
			}
			if item.err != nil {
				return "", item.err
			}

			// Partial events repeat the usage of the turn they belong to: the runner
			// forwards them verbatim and only the final event is authoritative.
			// Counting them on arrival would multiply every token metric by the chunk
			// count, so keep only the latest partial chunk unless the turn aborts
			// before the final event arrives.
			if item.event.Partial {
				if item.event.UsageMetadata != nil {
					lastPartial = item.event
				}
			} else {
				lastPartial = nil
				c.addUsage(ctx, item.event.UsageMetadata, item.event.ModelVersion)
				appendEventText(&response, item.event)
			}

			if err := turnCtx.Err(); err != nil {
				return "", err
			}
		}
	}
}

// forwardEvents consumes events on a separate goroutine so the caller can
// return promptly when its context expires or is canceled. ADK's node scheduler
// waits for all active tool and node goroutines to exit before closing the
// event iterator, so a non-cooperative tool or transport stall would otherwise
// block the caller past the deadline.
func forwardEvents(ctx context.Context, events iter.Seq2[*session.Event, error]) <-chan runnerItem {
	itemCh := make(chan runnerItem)
	go func() {
		defer close(itemCh)
		for event, err := range events {
			select {
			case itemCh <- runnerItem{event: event, err: err}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return itemCh
}

func appendEventText(b *strings.Builder, event *session.Event) {
	if event.Content == nil {
		return
	}
	for _, part := range event.Content.Parts {
		if part.Text != "" && !part.Thought {
			b.WriteString(part.Text)
		}
	}
}
