# Package `callbackserver`

Package `callbackserver` provides a client for interacting with the Tsunami
Callback Server (TCS) during out-of-band vulnerability detection. It manages a
singleton client initialized at scanner startup from the core configuration and
exposes helpers to generate secret-derived HTTP and DNS callback targets.
Vulnerability detectors and templated engine actions use it to poll TCS and
verify whether a scan target triggered an HTTP or DNS interaction.

## Services

-   **`Initialize` / `DefaultClient`**: `Initialize(ctx, config)` configures the
    package-level singleton `*Client` from `*config.Config` during scanner
    startup. `DefaultClient()` returns that singleton instance and panics if
    `Initialize` has not been called.
-   **`Client` and `IsCallbackServerEnabled`**: `Client` holds the callback
    server endpoint configuration alongside the core scanner configuration used
    by the shared HTTP client. `IsCallbackServerEnabled()` returns `true` only
    when public URIs are configured for all three endpoints (HTTP polling, HTTP
    recording, and DNS recording).
-   **`Client.GetHTTPCallbackURI` / `Client.GetDNSCallbackDomain`**: Derive a
    callback identifier from a `secret` string via `cbid.Generate` and return
    the corresponding HTTP recording URL or DNS recording domain. Both methods
    return `ErrInvalidConfig` when the callback server is not enabled.
-   **`Client.HasInteraction`**: `HasInteraction(ctx, secret)` polls the
    callback server's HTTP polling endpoint (`/?secret=<secret>`) and returns
    `true` if either an HTTP or DNS interaction was recorded. Non-`200 OK`
    responses return `(false, nil)`, whereas request, read, or JSON decoding
    errors wrap `ErrPollingRequest` (and disabled configs return
    `ErrInvalidConfig`).
-   **`PollingResult` (`polling.proto`)**: Protobuf message
    (`has_dns_interaction`, `has_http_interaction`) in `polling_go_proto` used
    to unmarshal JSON responses from the TCS polling endpoint.
-   **Sentinel Errors (`ErrInvalidConfig`, `ErrPollingRequest`,
    `ErrDomainCallbackWithIP`)**: `ErrInvalidConfig` indicates an unconfigured
    or incomplete callback server setup, and `ErrPollingRequest` wraps HTTP
    transport or response unmarshaling failures during polling.
    `ErrDomainCallbackWithIP` represents an unsupported IP-address configuration
    for domain callbacks.

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/common/clients/callbackserver"
    "github.com/google/goonami-scanner/core/config"
)

func checkCallback(
    ctx context.Context, cfg *config.Config, secret string,
) (bool, error) {
    if err := callbackserver.Initialize(ctx, cfg); err != nil {
        return false, err
    }

    client := callbackserver.DefaultClient()
    if !client.IsCallbackServerEnabled() {
        return false, nil
    }

    callbackURI, err := client.GetHTTPCallbackURI(secret)
    if err != nil {
        return false, err
    }
    _ = callbackURI // Send probe referencing callbackURI to target.

    return client.HasInteraction(ctx, secret)
}
```
