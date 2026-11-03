# Package `fakehttp`

Package `fakehttp` provides a concurrency-safe fake implementation of Goonami's
HTTP `Client` interface for unit tests. Tests can configure canned HTTP status
codes, transport errors, or custom request handlers without performing network
I/O, and inspect request invocation counts. It is commonly used to stub HTTP
client factories registered via `core/net/http` or to test HTTP middleware,
plugins, and modules in isolation.

## Services

-   **`Client`**: Concurrency-safe fake implementing Goonami's HTTP `Client`
    interface (`Do(*http.Request) (*http.Response, error)`).
-   **`DoFn`**: Handler signature
    `func(req *http.Request) (*http.Response, error)` for custom `Do`
    implementations.
-   **`New`**: `New(statusCode int, err error) *Client` creates a client
    returning `(nil, err)` when `err != nil`, `(nil, nil)` when
    `statusCode == 0` and `err == nil`, or an `*http.Response` with
    `StatusCode: statusCode` and `Body: http.NoBody`.
-   **`NewWithFunc` / `Client.OverrideDo`**: `NewWithFunc(fn DoFn) *Client`
    creates a client delegating `Do` to `fn`, while `OverrideDo(fn DoFn)`
    replaces the `Do` handler on an existing client.
-   **`Client.Do` / `Client.Calls`**:
    `Do(req *http.Request) (*http.Response, error)` increments the call counter
    and returns the configured override result, error, or status response.
    `Calls() int` returns the total number of `Do` invocations.

## Usage

```go
import (
    "io"
    "net/http"
    "strings"

    "github.com/google/goonami-scanner/common/testfakes/fakehttp"
    "github.com/google/goonami-scanner/core/config"
    goohttp "github.com/google/goonami-scanner/core/net/http"
)

// Register a canned fake HTTP client factory for tests.
goohttp.Register("testclient", func(
    *config.Config, *goohttp.ClientOptions,
) (goohttp.Client, error) {
    return fakehttp.New(http.StatusOK, nil), nil
})

// Use a custom handler and inspect invocation counts.
handler := func(req *http.Request) (*http.Response, error) {
    return &http.Response{
        StatusCode: http.StatusOK,
        Body:       io.NopCloser(strings.NewReader("hello")),
    }, nil
}
client := fakehttp.NewWithFunc(handler)
resp, err := client.Do(req)
calls := client.Calls() // 1
```
