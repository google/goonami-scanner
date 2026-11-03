# Package `llm`

Package `llm` provides a Goonami client for executing Large Language Model (LLM)
agent queries through the Agent Development Kit (ADK). It wraps an ADK
`agent.Agent` with configurable per-request timeouts, retry budgets, model tier
selection, and multi-turn response verification. During execution, the client
automatically records token usage and latency metrics, strips model
chain-of-thought parts from final text outputs, and optionally dumps full
session trajectories to the module artifacts directory.

## Services

-   **`Client` and `New`**: Wraps an ADK `agent.Agent` with Goonami's
    `LlmClientConfig` settings and an in-memory ADK session service initialized
    with `DefaultAppName` (`"goonami-clients-llm"`) and `DefaultUserID`
    (`"goonami"`). Construct an instance via `New(cfg, ag)`.
-   **`Client.RunWithFeedbackLoop`**: Executes an agent prompt (`*genai.Content`
    with a non-empty `Role`) with per-turn timeouts, retry delays, token and
    duration metrics, and optional validation via an `AgentResultVerifier`. Hard
    execution errors reset the session and retry from the initial prompt,
    whereas verification failures preserve the session and send the verifier's
    error back to the model as a follow-up user turn for refinement.
-   **`AgentResultVerifier`**: Callback signature
    `func(ctx context.Context, result string) error` used by
    `RunWithFeedbackLoop` to validate candidate model responses. Returning `nil`
    accepts the response, returning an error wrapping `ErrAbort` terminates the
    loop immediately, and returning any other error triggers conversational
    refinement if attempts remain.
-   **`ModelTier` and `GetModel`**: `ModelTier` (`ModelTierLite`,
    `ModelTierFast`, `ModelTierPro`) abstracts model capability tiers away from
    concrete model IDs. `GetModel(cfg, tier)` resolves the configured model name
    for the requested tier from `LlmClientConfig`, defaulting unrecognized tiers
    to the lite model.
-   **`TimeoutPerRequest`**: Helper `TimeoutPerRequest(cfg)` returning
    `timeout_per_request_seconds` from `LlmClientConfig` as a `time.Duration`
    (240s by default), commonly used to configure underlying model HTTP
    timeouts.
-   **Sentinel Errors (`ErrContentRequired`, `ErrMaxAttemptsReached`,
    `ErrAbort`, `ErrAgentRun`, `ErrSessionService`, `ErrRunnerCreation`)**:
    `RunWithFeedbackLoop` returns `ErrContentRequired` when the input content or
    role is missing, `ErrMaxAttemptsReached` when all attempts fail, or the
    verifier error directly when it wraps `ErrAbort`. `ErrAgentRun`,
    `ErrSessionService`, and `ErrRunnerCreation` classify internal ADK turn,
    session, and runner failures during retry attempts.
-   **`LlmClientConfig`, `ToolConfig`, and `HttpClientConfig`
    (`llm_client_config.proto`)**: Protobuf configuration messages defining
    per-request timeouts, max attempts, retry delays, model names per tier,
    trajectory dumping (`dump_trajectories`), and nested agent tool limits such
    as `HttpClientConfig` (allowed HTTP methods, per-service request caps, max
    response size, and forbidden path regexes).

## Usage

```go
import (
  "context"
  "errors"
  "fmt"
  "strings"

  "google.golang.org/adk/v2/agent/llmagent"
  "google.golang.org/adk/v2/model/gemini"
  "google.golang.org/genai"
  "github.com/google/goonami-scanner/common/clients/llm"
  "github.com/google/goonami-scanner/core/config"
)

func queryAgent(ctx context.Context, cfg *config.Config) (string, error) {
  modelCfg := &genai.ClientConfig{
    HTTPOptions: genai.HTTPOptions{
      Timeout: genai.Ptr(llm.TimeoutPerRequest(cfg)),
    },
  }
  modelName := llm.GetModel(cfg, llm.ModelTierFast)
  m, err := gemini.NewModel(ctx, modelName, modelCfg)
  if err != nil {
    return "", err
  }

  ag, err := llmagent.New(llmagent.Config{
    Name:        "example-agent",
    Model:       m,
    Instruction: "Reply with a non-empty summary.",
  })
  if err != nil {
    return "", err
  }

  client := llm.New(cfg, ag)
  prompt := &genai.Content{
    Role:  "user",
    Parts: []*genai.Part{{Text: "Summarize the target service banner."}},
  }
  verifier := func(ctx context.Context, result string) error {
    if result == "RATE_LIMITED" {
      return fmt.Errorf("%w: target rate limited", llm.ErrAbort)
    }
    if strings.TrimSpace(result) == "" {
      return errors.New("summary must not be empty")
    }
    return nil
  }
  return client.RunWithFeedbackLoop(ctx, prompt, verifier)
}
```
