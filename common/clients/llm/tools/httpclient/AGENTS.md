# Package `httpclient`

Package `httpclient` provides an Agent Development Kit (ADK) function tool that
lets LLM agents execute scoped HTTP requests against a target `NetworkService`
in Goonami. It enforces per-service guardrails from `HttpClientConfig`,
including allowed HTTP methods, path-only URI validation, forbidden path
patterns, per-service request budgets, in-scope redirect checks, and response
size limits. It supports both stateless requests and cookie-backed sessions,
returning the status code, final in-scope URI, high-signal response headers,
active cookies, and body content.

## Services

-   **`New`**: Initializes a service-scoped HTTP client tool from a core
    `Config` and target `NetworkService`, merging any `HttpClientConfig`
    overrides onto `DefaultConfig()`. It returns an ADK `tool.Tool` named
    `"httpclient"` backed by `Tool.Do`.
-   **`DefaultConfig`**: Returns the default `HttpClientConfig` protobuf message
    allowing `GET` and `POST` requests and applying Goonami's default forbidden
    path patterns alongside default request-count and response-size limits.
-   **`Tool` and `Tool.Do`**: Holds the per-service request counter, compiled
    forbidden-path regular expressions, and underlying stateless and
    cookie-storing HTTP clients. `Do` validates and executes a `Request` against
    the service's web root within the `agent.Context`, enforcing
    authority-scoped redirects and `MaxAnswerSizeBytes`.
-   **`Request` and `Header`**: JSON-schema-annotated input structs for
    `Tool.Do` specifying `Method`, an absolute path `URI` starting with `/`,
    optional `Headers` (`Name` and `Value` pairs), request body `Data`, and
    session flags. Setting `MaintainSession` persists cookies across stateful
    calls, while `ClearSession` resets the cookie jar before sending the
    request.
-   **`Response`**: JSON-schema-annotated output struct returned by `Tool.Do`
    containing `StatusCode`, `FinalURI` after any followed in-scope redirects,
    filtered `Headers` (`Content-Type`, `Location`, `Refresh`, `Server`, and
    `Www-Authenticate`), active `Cookies` (`map[string]string` from the cookie
    jar after creations, updates, and deletions), and raw body `Content`.
-   **`ErrInvalidURI`, `ErrInvalidMethod`, `ErrContentDenied`,
    `ErrTooManyRequests`**: Sentinel errors returned by `Tool.Do` when a URI
    lacks a leading `/` or contains `:`, the HTTP method is not allowed, the
    path matches a forbidden pattern, or the per-service request budget is
    exhausted.

## Usage

```go
package example

import (
  "google.golang.org/adk/v2/agent"
  "google.golang.org/adk/v2/agent/llmagent"
  "google.golang.org/adk/v2/model"
  "google.golang.org/adk/v2/tool"
  "github.com/google/goonami-scanner/common/clients/llm/tools/httpclient"
  "github.com/google/goonami-scanner/core/config"

  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func newProbeAgent(
    cfg *config.Config,
    mdl model.LLM,
    service *nspb.NetworkService,
) (agent.Agent, error) {
  httpTool, err := httpclient.New(cfg, service)
  if err != nil {
    return nil, err
  }

  return llmagent.New(llmagent.Config{
      Model:       mdl,
      Name:        "web-probe-agent",
      Instruction: "Inspect the target web service using httpclient.",
      Tools:       []tool.Tool{httpTool},
  })
}
```
