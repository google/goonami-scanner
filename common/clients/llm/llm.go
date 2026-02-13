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

// Package llm provides a client to query LLMs using the agent dev kit.
package llm

import (
	"context"
	"errors"
	"time"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/pborman/uuid"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

const (
	// DefaultAppName is the default application name to use for the LLM client.
	DefaultAppName = "goonami-clients-llm"

	// DefaultUserID is the default user ID to use for the LLM client.
	DefaultUserID = "goonami"
)

var (
	// ErrMaxAttemptsReached is returned when the maximum number of attempts to run the agent is
	// reached.
	ErrMaxAttemptsReached = errors.New("maximum number of attempts reached")

	// For most of Goonami's use cases, the in-memory session service is sufficient.
	defaultSessionService session.Service = session.InMemoryService()
)

// Client to perform LLMs queries using the agent dev kit.
type Client struct {
	config         *lccpb.LlmClientConfig
	coreConfig     *config.Config
	ag             agent.Agent
	appName        string
	userID         string
	sessionService session.Service
}

// New creates a new LLM client.
func New(config *config.Config, ag agent.Agent) (*Client, error) {
	return &Client{
		ag:             ag,
		config:         config.ClientsConfig().GetLlm(),
		coreConfig:     config,
		appName:        DefaultAppName,
		userID:         DefaultUserID,
		sessionService: defaultSessionService,
	}, nil
}

// AgentResultVerifier is a type of function that can perform validation of the LLM agent output.
type AgentResultVerifier func(ctx context.Context, result string) error

// Run an agent with retries and timeouts. This function provides a few abstraction:
//   - It provides timeout enforcement to the run of the agent.
//   - It provides a retry mechanism with a fixed backoff.
//   - It integrates the ability to check the validity of the response through a callback.
func (c *Client) Run(ctx context.Context, content *genai.Content, verifier AgentResultVerifier) (string, error) {
	ctx = log.ContextForModule(ctx, "clients/llm")
	retryDelay := time.Duration(c.config.GetRetryDelaySeconds()) * time.Second
	maxAttempts := int(c.config.GetMaxAttempts())

	for i := 0; i < maxAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		if i > 0 {
			log.DebugContextf(ctx, log.DebugLevelRequest, "waiting %v before next attempt", retryDelay)
			time.Sleep(retryDelay)
		}

		resp, err := c.runOnce(ctx, content)
		if err != nil {
			if len(err.Error()) > 200 {
				err = errors.New("(truncated) " + err.Error()[:200])
			}

			log.DebugContextf(ctx, log.DebugLevelRequest, "(attempt %d of %d) failed to run the agent: %v", i+1, maxAttempts, err)
			continue
		}

		if err := verifier(ctx, resp); err != nil {
			log.DebugContextf(ctx, log.DebugLevelRequest, "(attempt %d of %d) agent's response verification failed: %v", i+1, maxAttempts, err)
			continue
		}

		return resp, nil
	}

	return "", ErrMaxAttemptsReached
}

func (c *Client) runOnce(ctx context.Context, content *genai.Content) (string, error) {
	runnerConfig := runner.Config{
		Agent:          c.ag,
		SessionService: c.sessionService,
		AppName:        c.appName,
	}

	r, err := runner.New(runnerConfig)
	if err != nil {
		return "", err
	}

	sessionID := uuid.New()
	sessionReq := &session.CreateRequest{
		SessionID: sessionID,
		UserID:    c.userID,
		AppName:   c.appName,
	}
	_, err = defaultSessionService.Create(ctx, sessionReq)
	if err != nil {
		return "", err
	}

	timeout := time.Duration(c.config.GetTimeoutPerRequestSeconds()) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runConfig := agent.RunConfig{}
	events := r.Run(ctx, DefaultUserID, sessionID, content, runConfig)

	var response string
	for event, err := range events {
		if err != nil {
			return "", err
		}

		if err := ctx.Err(); err != nil {
			return "", err
		}

		if event.Content == nil {
			continue
		}

		for _, part := range event.Content.Parts {
			if part.Text != "" {
				response += part.Text
			}
		}
	}

	return response, nil
}
