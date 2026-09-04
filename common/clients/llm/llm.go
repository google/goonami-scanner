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
	"fmt"
	"strings"
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/pborman/uuid"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"
	"google.golang.org/protobuf/proto"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
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

	// ErrAgentRun is returned when the LLM agent fails to run.
	ErrAgentRun = errors.New("LLM agent run failed")

	// ErrSessionService is returned when there is an error with the session service.
	ErrSessionService = errors.New("session service error")

	// ErrRunnerCreation is returned when the agent runner cannot be created.
	ErrRunnerCreation = errors.New("failed to create agent runner")

	// ErrContentRequired is returned when the content is required.
	ErrContentRequired = errors.New("content is required (and must have a role)")

	// For most of Goonami's use cases, the in-memory session service is sufficient.
	defaultSessionService session.Service = session.InMemoryService()
)

// Client to perform LLMs queries using the agent dev kit.
type Client struct {
	config                  *lccpb.LlmClientConfig
	coreConfig              *config.Config
	ag                      agent.Agent
	appName                 string
	userID                  string
	sessionService          session.Service
	totalTokenCount         int32
	cachedContentTokenCount int32
}

// DefaultConfig returns the default configuration for the LLM client.
func DefaultConfig() *lccpb.LlmClientConfig {
	return lccpb.LlmClientConfig_builder{
		MaxAttempts:              proto.Int32(3),
		TimeoutPerRequestSeconds: proto.Int32(240),
		RetryDelaySeconds:        proto.Int32(10),
		LiteModel:                proto.String("gemini-3.5-flash-lite"),
		FastModel:                proto.String("gemini-3.6-flash"),
		ProModel:                 proto.String("gemini-3.1-pro-preview"),
	}.Build()
}

// ModelTier represents the tier of the model to use.
type ModelTier int

const (
	// ModelTierLite is a lightweight tier model.
	ModelTierLite ModelTier = iota
	// ModelTierFast is a fast tier model.
	ModelTierFast
	// ModelTierPro is a pro tier model.
	ModelTierPro
)

// GetModel returns the model name for a specific tier from the configuration.
func GetModel(config *config.Config, tier ModelTier) string {
	clientConfig := DefaultConfig()
	if config.ClientsConfig().HasLlm() {
		proto.Merge(clientConfig, config.ClientsConfig().GetLlm())
	}

	switch tier {
	case ModelTierLite:
		return clientConfig.GetLiteModel()
	case ModelTierFast:
		return clientConfig.GetFastModel()
	case ModelTierPro:
		return clientConfig.GetProModel()
	default:
		return clientConfig.GetLiteModel()
	}
}

// New creates a new LLM client.
func New(config *config.Config, ag agent.Agent) *Client {
	clientConfig := DefaultConfig()
	if config.ClientsConfig().HasLlm() {
		proto.Merge(clientConfig, config.ClientsConfig().GetLlm())
	}

	return &Client{
		ag:             ag,
		config:         clientConfig,
		coreConfig:     config,
		appName:        DefaultAppName,
		userID:         DefaultUserID,
		sessionService: defaultSessionService,
	}
}

// AgentResultVerifier is a type of function that can perform validation of the LLM agent output.
type AgentResultVerifier func(ctx context.Context, result string) error

// RunWithFeedbackLoop runs an agent with retries, timeouts, and response verification.
// When response verification fails, the active session is preserved and the verifier's diagnostic error
// is fed back to the model as the subsequent user turn for conversational refinement.
// Hard agent execution failures reset the session and restart from the initial prompt.
func (c *Client) RunWithFeedbackLoop(ctx context.Context, content *genai.Content, verifier AgentResultVerifier) (string, error) {
	ctx = log.ContextForModule(ctx, "clients/llm")

	if content == nil || content.Role == "" {
		return "", ErrContentRequired
	}

	defer func() {
		log.DebugContextf(ctx, log.DebugLevelService, "Agent token usage: total=%d (cached=%d)", c.totalTokenCount, c.cachedContentTokenCount)
	}()

	retryDelay := time.Duration(c.config.GetRetryDelaySeconds()) * time.Second
	maxAttempts := int(c.config.GetMaxAttempts())

	var sessionID string
	turnContent := content

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		if attempt > 1 {
			log.DebugContextf(ctx, log.DebugLevelService, "waiting %v before next attempt", retryDelay)
			time.Sleep(retryDelay)
		}

		nextSessionID, resp, err := c.runTurn(ctx, sessionID, turnContent)
		if err != nil {
			log.DebugContextf(ctx, log.DebugLevelService, "(attempt %d of %d) failed to run the agent: %v", attempt, maxAttempts, err)
			sessionID = ""
			turnContent = content
			continue
		}

		if verifier != nil {
			if err := verifier(ctx, resp); err != nil {
				log.DebugContextf(ctx, log.DebugLevelService, "(attempt %d of %d) agent's response verification failed: %v", attempt, maxAttempts, err)
				sessionID = nextSessionID
				turnContent = feedbackContent(err)
				continue
			}
		}

		return resp, nil
	}

	return "", ErrMaxAttemptsReached
}

// Run an agent with retries, timeouts, and optional output verification.
// Callers requiring verification should migrate to RunWithFeedbackLoop.
func (c *Client) Run(ctx context.Context, content *genai.Content, verifier AgentResultVerifier) (string, error) {
	return c.RunWithFeedbackLoop(ctx, content, verifier)
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

	r, err := runner.New(runner.Config{
		Agent:          c.ag,
		SessionService: c.sessionService,
		AppName:        c.appName,
	})
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrRunnerCreation, err)
	}

	timeout := time.Duration(c.config.GetTimeoutPerRequestSeconds()) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	events := r.Run(ctx, c.userID, sessionID, content, agent.RunConfig{})

	var response strings.Builder
	for event, err := range events {
		if err != nil {
			return "", "", fmt.Errorf("%w: %v", ErrAgentRun, err)
		}

		if event.UsageMetadata != nil {
			c.totalTokenCount += event.UsageMetadata.TotalTokenCount
			c.cachedContentTokenCount += event.UsageMetadata.CachedContentTokenCount
		}

		if event.Content == nil {
			continue
		}

		for _, part := range event.Content.Parts {
			if part.Text != "" && !part.Thought {
				response.WriteString(part.Text)
			}
		}
	}

	return sessionID, response.String(), nil
}

// createSession creates a new unique session with the configured session service.
func (c *Client) createSession(ctx context.Context) (string, error) {
	if c.sessionService == nil {
		return "", ErrSessionService
	}

	sessionID := uuid.New()
	_, err := c.sessionService.Create(ctx, &session.CreateRequest{
		SessionID: sessionID,
		UserID:    c.userID,
		AppName:   c.appName,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSessionService, err)
	}
	return sessionID, nil
}

// feedbackContent formats the verifier failure diagnostic as a user turn for refinement.
func feedbackContent(err error) *genai.Content {
	return &genai.Content{
		Role: "user",
		Parts: []*genai.Part{{
			Text: fmt.Sprintf("Verification of your previous response failed:\n%v\n\nPlease correct the issues and provide an updated response.", err),
		}},
	}
}
