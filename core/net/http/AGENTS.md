# Package `http`

Package `http` provides Goonami's pluggable HTTP client abstraction, registry,
and request-handling utilities. Concrete client backends register factories via
`Register`, allowing callers to obtain metrics-instrumented and optionally
rate-limit-retriable clients through `NewClient` or `SharedClient` based on the
core scanner configuration. It also defines `ClientOptions` for per-client
cookie, TLS, redirect, authority-scope, and path-filtering policies, along with
helpers for bounded response-body reads and destructive URL path filtering.

## Services

-   **`Client` and `CreateHTTPClientFn`**: `Client` defines the common
    `Do(*http.Request) (*http.Response, error)` interface implemented by Goonami
    HTTP backends, and `CreateHTTPClientFn` is the factory signature
    `func(*config.Config, *ClientOptions) (Client, error)` used to construct
    them.
-   **`Register` and `CurrentClientName`**: `Register(name, factory)` registers
    a named `CreateHTTPClientFn` implementation in the package-level client
    registry. `CurrentClientName(cfg)` returns the active client backend name
    configured in `cfg.GlobalConfig().GetHttpClient()`.
-   **`NewClient` and `SharedClient`**: `NewClient(cfg, options)` instantiates
    the registered client selected by `CurrentClientName(cfg)`, wraps it to
    record `metrics.HTTPRequests` and transport-level
    `metrics.HTTPRequestErrors`, and adds HTTP 429
    exponential-backoff/`Retry-After` retries when `options.RetryOnRateLimit` is
    enabled. `SharedClient(cfg)` lazily initializes and returns a process-wide
    singleton `Client` using `DefaultClientOptions()`, panicking if
    initialization fails.
-   **`ClientOptions` and `DefaultClientOptions`**: `ClientOptions` configures
    ephemeral client behavior—`StoreCookies`, `EnforceTLSCertVerification`,
    `DisableFollowRedirects`, `AllowedAuthorities`, `ForbiddenPaths`, and
    `RetryOnRateLimit`. `DefaultClientOptions()` disables cookie storage, TLS
    verification, and rate-limit retries, enables redirects across any
    authority, and populates `ForbiddenPaths` from the default forbidden path
    patterns.
-   **`ClientOptions.LoadAuthorities`, `IsAuthorityAllowed`, and
    `IsRedirectAllowed`**: `LoadAuthorities(service)` populates
    `AllowedAuthorities` from a `NetworkService` endpoint via
    `netendpoint.ToURIAuthorities` (returning `nil` when no endpoint is set).
    `IsAuthorityAllowed(targetURL)` checks host and port scope (resolving
    default HTTP/HTTPS ports and IPv6 brackets), and
    `IsRedirectAllowed(targetURL)` combines redirect enablement, authority
    scope, and `ForbiddenPaths` checks.
-   **`DefaultForbiddenPathPatterns` and `IsURLPathForbidden`**:
    `DefaultForbiddenPathPatterns()` returns a cloned slice of case-insensitive,
    word-boundary-anchored regex strings that block destructive or lifecycle
    keywords (`abort`, `delete`, `drop`, `hup`, `kill`/`killall`, `quit`,
    `remove`) without matching benign substrings.
    `IsURLPathForbidden(targetURL, forbidden)` canonicalizes the URL path and
    unescapes the query string before matching against `forbidden`, ignoring the
    scheme and authority.
-   **`ReadBody`**: `ReadBody(resp, maxsize)` reads `resp.Body` into a
    `maxsize`-byte buffer and returns the payload when its length is strictly
    less than `maxsize`. It returns `ErrPageTooBig` if the body is at least
    `maxsize` bytes, `io.EOF` if the body is empty, or any underlying read
    error.
-   **Sentinel Errors (`ErrPageTooBig`, `ErrRateLimited`)**: `ErrPageTooBig` is
    returned when a response body reaches or exceeds the maximum allowed byte
    size (such as in `ReadBody`). `ErrRateLimited` is returned when
    `RetryOnRateLimit` is enabled and HTTP 429 responses persist across all
    configured attempts or return a `Retry-After` delay exceeding
    `max_http_retry_after_seconds`.

## Usage

```go
package example

import (
    "context"
    "errors"
    "net/http"

    "github.com/google/goonami-scanner/core/config"
    goohttp "github.com/google/goonami-scanner/core/net/http"

    nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func fetchBounded(
    ctx context.Context, cfg *config.Config, targetURL string,
) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
    if err != nil {
        return nil, err
    }

    resp, err := goohttp.SharedClient(cfg).Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := goohttp.ReadBody(resp, 4096)
    if errors.Is(err, goohttp.ErrPageTooBig) {
        return nil, nil
    }
    return body, err
}

func newScopedClient(
    cfg *config.Config, service *nspb.NetworkService,
) (goohttp.Client, error) {
    opts := goohttp.DefaultClientOptions()
    opts.StoreCookies = true
    opts.RetryOnRateLimit = true
    if err := opts.LoadAuthorities(service); err != nil {
        return nil, err
    }
    return goohttp.NewClient(cfg, opts)
}
```
