# Package `cache`

Package `cache` provides disk-backed caching of serialized authentication
strategies for the `dt/adkweakcreds` detector plugin. It keys cached strategies
by the web-identity response hash of a target service's login path so identical
login pages can reuse previously discovered strategies without invoking the LLM
agent. During lookups, it reuses pre-crawled page hashes attached to the target
`NetworkService` before falling back to live HTTP probing.

## Services

-   **`Index`**: Thread-safe, disk-backed strategy index (`index.json`) whose
    `HashToPath` field maps hex web-identity page hashes to URL paths. Strategy
    payloads are stored alongside the index under `cache/<hash>.strategy.json`.
-   **`Load(ctx, path)`**: Loads an `*Index` from `path`, returning `nil` when
    `path` is empty so callers can treat caching as disabled. When `index.json`
    is missing or cannot be unmarshaled, it logs a warning and returns an
    initialized empty `*Index`.
-   **`(*Index).Add(ctx, cfg, service, path, strategy)`**: Fetches `path` on
    `service` over HTTP, hashes the response, and writes both
    `cache/<hash>.strategy.json` and the updated `index.json` under a mutex
    lock. Acts as a no-op when the receiver is `nil`, and returns an error on
    HTTP 429 rate limiting, request/hashing failures, or disk write errors.
-   **`(*Index).FindForService(ctx, cfg, service)`**: Looks up a cached strategy
    for `service`, returning `(strategy, true)` on a hash match or
    `(nil, false)` on a miss, error, or `nil` receiver. For each indexed path,
    it first checks pre-crawled `CONTENT_TYPE_HASH` results on `service`
    (skipping network fetches for any already-crawled path) before fetching and
    hashing uncrawled paths once over HTTP.

## Usage

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/plugins/detectors/adkweakcreds/cache"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func getOrCacheStrategy(
    ctx context.Context,
    cfg *config.Config,
    service *nspb.NetworkService,
    discover func() (strategy []byte, loginPath string, err error),
) ([]byte, error) {
  cacheDir, err := cfg.GetCacheForModule("dt/adkweakcreds")
  if err != nil {
    cacheDir = ""
  }
  idx := cache.Load(ctx, cacheDir)

  if data, found := idx.FindForService(ctx, cfg, service); found {
    return data, nil
  }

  data, loginPath, err := discover()
  if err != nil {
    return nil, err
  }
  if err := idx.Add(ctx, cfg, service, loginPath, data); err != nil {
    // Log warning and continue with the discovered strategy.
  }
  return data, nil
}
```
