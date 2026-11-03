# Package `fakellmagent`

Package `fakellmagent` provides in-memory test doubles for Agent Development Kit
(ADK) agents, invocation contexts, and language models. It enables deterministic
unit testing of LLM-driven Goonami clients, agent tools, and vulnerability
detectors without live model backends or credentials. Callers can stub static or
dynamic `agent.Agent` event streams, wrap standard Go contexts as
`agent.Context` values for tool tests, and record `model.LLM` requests.

## Services

-   **`FakeAgent` (`New`, `NewWithSimpleAnswer`, `NewWithError`)**: Test
    implementation of `agent.Agent` (`Name` and `Description` return
    `"fake-agent"`, `SubAgents` returns `nil`) whose `Run` method yields
    preconfigured `(*session.Event, error)` pairs. `New(events, errors)`
    requires equal-length slices (panicking on mismatch), while
    `NewWithSimpleAnswer(answer)` and `NewWithError(err)` construct
    single-result agents for common test cases.
-   **`NewWithFunc`, `NewWithSeq`, `RunFn`, and `RunSeqFn`**: Dynamic
    constructors for `FakeAgent` when responses depend on the
    `agent.InvocationContext` or turn state. `NewWithFunc(fn)` invokes a `RunFn`
    (`func(agent.InvocationContext) (*session.Event, error)`) to yield one
    result per `Run` call, whereas `NewWithSeq(fn)` delegates `Run` directly to
    a `RunSeqFn`
    (`func(agent.InvocationContext) iter.Seq2[*session.Event, error]`).
-   **`FakeAgent.WithOnPrompt`**: Registers a `func(string)` callback invoked at
    the start of `Run` with `ctx.UserContent().Parts[0].Text` when `ctx`
    provides at least one user content part, returning the `*FakeAgent` receiver
    for chaining.
-   **`TextEvent`**: Helper `TextEvent(text)` that constructs a `*session.Event`
    containing a `model.LLMResponse` with a single text `*genai.Part`.
-   **`FakeContext` and `NewContext`**: Wraps a standard `context.Context` via
    `NewContext(ctx)` to satisfy `agent.Context` in tool unit tests. It
    delegates `Deadline`, `Done`, `Err`, and `Value` directly to the underlying
    context.
-   **`FakeModel` and `NewModel`**: Test implementation of `model.LLM` (`Name`
    returns `"fake-model"`) initialized with equal-length `responses` and
    `errors` slices (panicking on mismatch). `GenerateContent` records each
    incoming `*model.LLMRequest` for inspection via `Requests()` and yields the
    configured `(*model.LLMResponse, error)` sequence.

## Usage

```go
package example_test

import (
  "testing"

  "google.golang.org/adk/v2/agent"
  "google.golang.org/adk/v2/agent/llmagent"
  "google.golang.org/adk/v2/model"
  "google.golang.org/adk/v2/session"
  "google.golang.org/genai"
  "github.com/google/goonami-scanner/common/clients/llm"
  "github.com/google/goonami-scanner/common/testfakes/fakellmagent"
  "github.com/google/goonami-scanner/core/config"
)

func stubAgent(t *testing.T, cfg *config.Config) {
  var gotPrompt string
  ag := fakellmagent.NewWithFunc(
      func(ic agent.InvocationContext) (*session.Event, error) {
        return fakellmagent.TextEvent("ok"), nil
      },
  ).WithOnPrompt(func(prompt string) {
    gotPrompt = prompt
  })

  prompt := &genai.Content{
    Role:  "user",
    Parts: []*genai.Part{{Text: "inspect banner"}},
  }
  got, err := llm.New(cfg, ag).RunWithFeedbackLoop(t.Context(), prompt, nil)
  if err != nil || got != "ok" || gotPrompt != "inspect banner" {
    t.Fatalf("got (%q, %v), prompt %q", got, err, gotPrompt)
  }
}

func recordModelRequests(t *testing.T, cfg *config.Config) {
  fakeLLM := fakellmagent.NewModel(
      []*model.LLMResponse{{
        Content: &genai.Content{
          Role:  "model",
          Parts: []*genai.Part{{Text: "done"}},
        },
      }},
      []error{nil},
  )
  ag, err := llmagent.New(llmagent.Config{
    Name:  "test-agent",
    Model: fakeLLM,
  })
  if err != nil {
    t.Fatalf("llmagent.New() unexpected error: %v", err)
  }

  prompt := &genai.Content{
    Role:  "user",
    Parts: []*genai.Part{{Text: "hello"}},
  }
  if _, err := llm.New(cfg, ag).RunWithFeedbackLoop(
      t.Context(), prompt, nil,
  ); err != nil {
    t.Fatalf("RunWithFeedbackLoop() unexpected error: %v", err)
  }
  if len(fakeLLM.Requests()) != 1 {
    t.Fatalf("recorded %d requests, want 1", len(fakeLLM.Requests()))
  }
}
```
