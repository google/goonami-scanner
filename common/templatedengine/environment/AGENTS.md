# Package `environment`

Package `environment` manages workflow-scoped key-value variables for Goonami's
templated detection engine. It seeds target network service metadata,
timestamps, and callback server parameters prior to action execution, and
supports runtime variable interpolation and regular-expression value extraction
across plugin steps. Action runners share an `Environment` instance throughout a
workflow run to pass dynamic state such as extracted tokens or callback secrets
between actions.

## Services

-   **`Environment` and `New`**: Stores string key-value variables for a
    templated detector workflow, constructed via `New(cfg *config.Config)` over
    an unsynchronized in-memory map.
-   **`Environment.InitializeFor`**: `InitializeFor(ctx, service)` populates the
    workflow start timestamp (`VarUtilTimestamp`), target endpoint metadata
    (`VarNetService*`), and—when configured and enabled—per-run callback server
    parameters (`VarCallback*`) from a `*nspb.NetworkService`.
-   **`Environment.Set` and `Environment.Get`**: `Set(key, value)` writes or
    overwrites a variable in the environment, and `Get(key)` returns its value
    along with a boolean presence indicator.
-   **`Environment.Substitute`**: `Substitute(ctx, template)` replaces
    `{{ VAR_NAME }}` placeholders (requiring single spaces around alphanumeric
    or underscore names) with stored values. Unknown variables log a warning and
    remain unsubstituted in the output.
-   **`Environment.Extract`**: `Extract(ctx, content, varname, pattern)`
    compiles `pattern` as a regular expression and stores the first capture
    group match (`matches[1]`) from `content` into `varname`.
-   **`ErrInvalidRegexp` and `ErrFailedExtraction`**: Sentinel errors wrapped
    and returned by `Extract` when `pattern` fails regular-expression
    compilation or when `content` produces no capture group match.
-   **Service and Utility Variable Keys (`VarUtilTimestamp`,
    `VarNetService*`)**: Built-in variable name constants populated by
    `InitializeFor` for workflow start time in milliseconds (`VarUtilTimestamp`)
    and target web root URL with trailing slash, protocol, hostname, port, and
    IP (`VarNetServiceBaseURL`, `VarNetServiceProtocol`,
    `VarNetServiceHostname`, `VarNetServicePort`, `VarNetServiceIP`).
-   **Callback Variable Keys (`VarCallback*`)**: Built-in variable name
    constants for callback server parameters (`VarCallbackURI`,
    `VarCallbackDNS`, `VarCallbackSecret`, `VarCallbackAddress`,
    `VarCallbackPort`) generated per service and workflow run when callback
    recording is active.
-   **Testing Constants (`VarTesting*`)**: Reserved variable keys and magic
    string markers (`VarTestingMagicPrefix`, `VarTestingMagicAnyURI`,
    `VarTestingMagicEchoServer`, `VarTestingDisableSleep`) used in templated
    engine tests to stub URIs, echo HTTP requests, or bypass sleep actions.

## Usage

```go
import (
  "context"
  "errors"

  "github.com/google/goonami-scanner/common/templatedengine/environment"
  "github.com/google/goonami-scanner/core/config"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func prepareTargetURL(
    ctx context.Context,
    cfg *config.Config,
    service *nspb.NetworkService,
    respBody string,
) (string, error) {
  env := environment.New(cfg)
  if err := env.InitializeFor(ctx, service); err != nil {
    return "", err
  }

  err := env.Extract(ctx, respBody, "token", `csrf_token="([a-zA-Z0-9_-]+)"`)
  if errors.Is(err, environment.ErrFailedExtraction) {
    env.Set("token", "default")
  } else if err != nil {
    return "", err
  }

  tmpl := "{{ T_NS_BASEURL }}verify?csrf={{ token }}"
  return env.Substitute(ctx, tmpl), nil
}
```
