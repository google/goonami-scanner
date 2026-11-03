# Package `actions`

Package `actions` implements the step runners executed by Goonami's templated
vulnerability detection engine (`templatedengine`). Each runner implements
`ActionRunner` to execute a `PluginAction` variant—HTTP requests, out-of-band
callback server checks, or sleep utilities—against a target `NetworkService`
using a shared variable `Environment`. The package also provides sentinel errors
so callers can distinguish negative vulnerability checks from invalid or missing
action definitions.

## Services

-   **`ActionRunner`**: Interface defining
    `Run(ctx, service, action, env) error` to execute a `PluginAction` against a
    `NetworkService` with variable state in `Environment`. Returns `nil` when
    the action succeeds or an error describing why execution or validation
    failed.
-   **`HTTPActionRunner` / `NewHTTPActionRunner`**: Executes `HttpAction`
    requests across one or more candidate URIs (succeeding on the first match)
    with `Environment` variable substitution in URIs, headers, bodies,
    expectations, and extraction patterns, while honoring client options
    (`DisableFollowRedirects`, `IgnoreHttpClientErrors`). Validates expected
    HTTP status codes, evaluates body or header `contains` checks (`ExpectAll`
    or `ExpectAny`), and extracts regex matches into `Environment` (`ExtractAll`
    or `ExtractAny`).
-   **`CallbackServerActionRunner` / `NewCallbackServerActionRunner`**: Executes
    `CallbackServerAction` (`CHECK`) steps by retrieving
    `environment.VarCallbackSecret` from `Environment` and querying
    `callbackserver.DefaultClient().HasInteraction`. Returns a wrapped
    `ErrActionFailed` if the callback server is disabled, the secret is missing,
    or no interaction was recorded, and `ErrInvalidAction` for unsupported
    action types.
-   **`UtilityActionRunner`**: Zero-value `ActionRunner` that executes
    `UtilityAction` steps such as `SleepUtilityAction`, sleeping for
    `DurationMs` milliseconds unless `environment.VarTestingDisableSleep` is
    `"true"` in `Environment`. Returns a wrapped `ErrInvalidAction` when the
    action is missing a supported utility payload.
-   **Sentinel Errors (`ErrActionFailed`, `ErrInvalidAction`,
    `ErrActionNotFound`)**: `ErrActionFailed` indicates a non-fatal check
    failure meaning the vulnerability was not detected, while `ErrInvalidAction`
    and `ErrActionNotFound` report malformed, unsupported, or missing action
    definitions.

## Usage

```go
import (
    "context"
    "errors"

    "github.com/google/goonami-scanner/common/templatedengine/actions"
    "github.com/google/goonami-scanner/common/templatedengine/environment"
    "github.com/google/goonami-scanner/core/config"

    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
    tpb "github.com/google/tsunami-security-scanner-plugins/templated/templateddetector/proto/templated_plugin_go_proto"
)

func runStep(
    ctx context.Context,
    cfg *config.Config,
    service *nspb.NetworkService,
    action *tpb.PluginAction,
    env *environment.Environment,
) (matched bool, err error) {
    var runner actions.ActionRunner
    switch {
    case action.GetHttpRequest() != nil:
        runner = actions.NewHTTPActionRunner(cfg)
    case action.GetCallbackServer() != nil:
        runner = actions.NewCallbackServerActionRunner(cfg)
    case action.GetUtility() != nil:
        runner = &actions.UtilityActionRunner{}
    default:
        return false, actions.ErrInvalidAction
    }

    if err := runner.Run(ctx, service, action, env); err != nil {
        if errors.Is(err, actions.ErrActionFailed) {
            return false, nil
        }
        return false, err
    }
    return true, nil
}
```
