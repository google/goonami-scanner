# Package `simpleclient`

Package `simpleclient` provides Goonami's standard-library HTTP client
implementation (`SimpleClient`) backed by `net/http` and token-bucket rate
limiting. On package initialization, it registers a client factory under
`"simpleclient"` with `core/net/http` so entrypoints and tests can enable it via
a blank import. It enforces per-request timeouts, QPS limits, redirect caps, TLS
certificate verification, optional cookie storage, and redirect scope rules from
scanner configuration and `ClientOptions`.

## Services

-   **Registry Registration (`"simpleclient"`)**: Package initialization
    registers a client factory under `"simpleclient"` via `Register` in
    `core/net/http`. Entrypoints and tests typically blank-import the package so
    `NewClient` and `SharedClient` can instantiate it from scanner
    configuration.
-   **`SimpleClient`**: Struct wrapping a standard-library `*http.Client` and a
    `*rate.Limiter` to implement the `Client` interface in `core/net/http`.
-   **`New`**: `New(cfg, options)` constructs a `*SimpleClient` configured with
    `cfg.TimeoutPerRequest()`, QPS rate limiting from
    `max_http_requests_per_second` (unlimited when `0`), optional cookie jar
    storage (`StoreCookies`), TLS verification (`EnforceTLSCertVerification`),
    and redirect checks. It defaults `nil` `options` to `DefaultClientOptions()`
    and returns `ErrConfigNil` if `cfg` is `nil`.
-   **`SimpleClient.Do`**: `Do(req)` waits on the rate limiter using
    `req.Context()`, executes the underlying HTTP request, and logs the method,
    path, and status code or error at `log.DebugLevelRequest`. Disallowed
    redirects (`!options.IsRedirectAllowed`) stop redirect following and return
    the redirect response, whereas reaching `max_http_redirects` increments
    `metrics.BudgetExhausted` and fails with `ErrTooManyRedirects`.
-   **Sentinel Errors (`ErrConfigNil`, `ErrTooManyRedirects`)**: `ErrConfigNil`
    is returned by `New` when a `nil` `*config.Config` is provided.
    `ErrTooManyRedirects` is returned during `Do` when a request's redirect
    chain reaches the configured `max_http_redirects` limit.

## Usage

```go
package example

import (
    "context"
    "net/http"

    "github.com/google/goonami-scanner/core/config"
    goohttp "github.com/google/goonami-scanner/core/net/http"
    _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
)

func fetchViaRegistry(
    ctx context.Context, cfg *config.Config, targetURL string,
) (*http.Response, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
    if err != nil {
        return nil, err
    }
    return goohttp.SharedClient(cfg).Do(req)
}
```

```go
package example

import (
    "context"
    "net/http"

    "github.com/google/goonami-scanner/core/config"
    goohttp "github.com/google/goonami-scanner/core/net/http"
    "github.com/google/goonami-scanner/core/net/http/simpleclient"
)

func fetchDirectly(
    ctx context.Context, cfg *config.Config, targetURL string,
) (*http.Response, error) {
    opts := goohttp.DefaultClientOptions()
    opts.StoreCookies = true
    opts.EnforceTLSCertVerification = true

    client, err := simpleclient.New(cfg, opts)
    if err != nil {
        return nil, err
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
    if err != nil {
        return nil, err
    }
    return client.Do(req)
}
```
