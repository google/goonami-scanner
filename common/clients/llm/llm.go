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
	"time"

	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"github.com/google/goonami-scanner/core/metrics"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/session"
	"google.golang.org/genai"

	lccpb "github.com/google/goonami-scanner/common/clients/llm/llm_client_config_go_proto"
)

const (
	// DefaultAppName is the default application name to use for the LLM client.
	DefaultAppName = "goonami-clients-llm"

	// DefaultUserID is the default user ID to use for the LLM client.
	DefaultUserID = "goonami"

	// llmMetricsModule is the module name this client reports under, both in logs
	// and in the module label of its metrics.
	llmMetricsModule = "clients/llm"
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

	// ErrAbort can be wrapped by an AgentResultVerifier to stop RunWithFeedbackLoop immediately
	// instead of asking the model to correct its answer. Use it for failures the model cannot fix,
	// such as the target rate limiting the verification requests.
	ErrAbort = errors.New("agent run aborted by verifier")
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
	clientConfig := config.ClientsConfig().GetLlm()

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

// TimeoutPerRequest returns the per-request timeout for the LLM client from the configuration.
func TimeoutPerRequest(config *config.Config) time.Duration {
	return time.Duration(config.ClientsConfig().GetLlm().GetTimeoutPerRequestSeconds()) * time.Second
}

// New creates a new LLM client.
func New(config *config.Config, ag agent.Agent) *Client {
	clientConfig := &lccpb.LlmClientConfig{}
	if config.ClientsConfig().HasLlm() {
		clientConfig = config.ClientsConfig().GetLlm()
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
// Verifier errors wrapping ErrAbort end the run immediately and are returned as is.
func (c *Client) RunWithFeedbackLoop(ctx context.Context, content *genai.Content, verifier AgentResultVerifier) (result string, err error) {
	ctx = log.ContextForModule(ctx, llmMetricsModule)

	if content == nil || content.Role == "" {
		return "", ErrContentRequired
	}

	start := time.Now()
	defer func() {
		metrics.LLMDuration.Observe(ctx, time.Since(start).Seconds(), metrics.ErrorClass(err))
		log.DebugContextf(ctx, log.DebugLevelService, "Agent token usage: total=%d (cached=%d)", c.totalTokenCount, c.cachedContentTokenCount)
	}()

	retryDelay := time.Duration(c.config.GetRetryDelaySeconds()) * time.Second
	maxAttempts := int(c.config.GetMaxAttempts())
	turnTimeout := time.Duration(c.config.GetTimeoutPerRequestSeconds()) * time.Second

	loopTimeout := time.Duration(maxAttempts)*turnTimeout + time.Duration(max(0, maxAttempts-1))*retryDelay
	loopCtx, cancel := context.WithTimeout(ctx, loopTimeout)
	defer cancel()

	var sessionID string
	turnContent := content

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := loopCtx.Err(); err != nil {
			return "", err
		}

		if attempt > 1 {
			log.DebugContextf(ctx, log.DebugLevelService, "waiting %v before next attempt", retryDelay)
			select {
			case <-time.After(retryDelay):
			case <-loopCtx.Done():
				return "", loopCtx.Err()
			}
		}

		nextSessionID, resp, err := c.runTurn(loopCtx, sessionID, turnContent)
		if err != nil {
			log.DebugContextf(ctx, log.DebugLevelService, "(attempt %d of %d) failed to run the agent: %v", attempt, maxAttempts, err)
			// Check the caller's ctx rather than loopCtx so a final-attempt turn
			// timeout still returns ErrMaxAttemptsReached, while caller cancellation
			// or deadline expiration returns immediately.
			if err := ctx.Err(); err != nil {
				return "", err
			}
			sessionID = ""
			turnContent = content
			continue
		}

		if verifier != nil {
			if err := verifier(loopCtx, resp); err != nil {
				if errors.Is(err, ErrAbort) {
					return "", err
				}
				log.DebugContextf(ctx, log.DebugLevelService, "(attempt %d of %d) agent's response verification failed: %v", attempt, maxAttempts, err)
				// Check the caller's ctx rather than loopCtx so a final-attempt timeout
				// still returns ErrMaxAttemptsReached, while caller cancellation or
				// deadline expiration returns immediately.
				if err := ctx.Err(); err != nil {
					return "", err
				}
				sessionID = nextSessionID
				turnContent = feedbackContent(err)
				continue
			}
		}

		return resp, nil
	}

	// The agent never produced an acceptable answer within its budget.
	metrics.BudgetExhausted.Add(ctx, 1,
		metrics.Module(llmMetricsModule),
		metrics.LimitName(metrics.LimitMaxAttempts))

	return "", ErrMaxAttemptsReached
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
