# Package `cache`

Package `cache` provides a thread-safe, in-memory HTTP response cache with
`singleflight` request coalescing for the `fp/webidentity` fingerprinter. It
lets passive crawl results be stored once and reused across fingerprint
workflows while ensuring concurrent active probes for the same method and URL
execute only one HTTP request.

## Services

-   **`Cache`, `New(client, opts...)`, and `WithMaxBodyBytes(max)`**:
    In-memory response store keyed by normalized HTTP method and lowercased
    scheme/host URL, defaulting to a 10 MiB active response body read cap.
-   **`(*Cache).Put(method, rawURL, resp, body)`**: Stores or replaces a cached
    response entry (cloning headers and body bytes) while preserving first-seen
    insertion order.
-   **`(*Cache).Get(method, rawURL)` and `(*Cache).All()`**: Looks up a single
    cached response entry or returns a snapshot slice of all entries in
    insertion order.
-   **`(*Cache).Fetch(ctx, req)`**: Returns an existing cached entry if present,
    or executes `req` via `HTTPDoer` under `singleflight` coalescing and stores
    the bounded response body.
-   **`CachedResponse` and `(*CachedResponse).Response()`**: Immutable response
    snapshot containing status code, status text, cloned headers, body bytes,
    parsed URL, and HTTP method, with a helper to construct a fresh readable
    `*http.Response`.
-   **Sentinel errors (`ErrNilRequest`, `ErrNoClient`)**: Returned by `Fetch`
    when invoked with a `nil` request or when no `HTTPDoer` client was provided
    and the requested entry is not already cached.

## Usage

```go
import (
  "context"
  "net/http"

  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity/cache"
)

func fetchOrReuse(
    ctx context.Context,
    client cache.HTTPDoer,
    targetURL string,
) (*cache.CachedResponse, error) {
  c := cache.New(client)
  req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
  if err != nil {
    return nil, err
  }
  return c.Fetch(ctx, req)
}
```
