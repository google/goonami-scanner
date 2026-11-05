# Package `httpcrawler`

Package `httpcrawler` provides a concurrent, scope-aware HTTP web crawler client
for Goonami plugins such as web fingerprinting. It fetches pages via a
run-scoped Goonami HTTP client (`http.NewClient`), invokes a caller-supplied
callback on each response body, and recursively extracts and queues HTML links
within configured depth, page size, concurrency, and request limits. Both
discovered HTML links and HTTP `3xx` redirects are filtered against domain/path
scopes and forbidden-path regular expressions (`exclusions`), and queued URLs
are normalized (iteratively URL-decoded and stripped of query strings,
fragments, and trailing slashes) so each base path is visited at most once per
crawl run.

## Services

-   **`Crawler`**: Interface defining
    `Crawl(context.Context, PageCallback, []string) (*CrawlStats, error)` for
    starting a web crawl from seed URLs.
-   **`SimpleCrawler`**: Concurrent `Crawler` implementation that fetches pages,
    extracts HTML links, enforces scope and regex path exclusions, and skips
    timed-out, oversized, or empty responses without aborting the run. Its
    `max_requests` budget is tracked on the `SimpleCrawler` instance and shared
    across calls to `Crawl`.
-   **`NewSimpleCrawler`**: Constructs a `*SimpleCrawler` from `*config.Config`,
    merging any configured `HttpCrawlerClientConfig` over
    `DefaultClientConfig()` and replacing default exclusions when custom
    `exclusions` are set.
-   **`PageCallback`**: Callback signature `func(ctx context.Context, info
    *PageInfo, resp *http.Response, content []byte) error` invoked on every
    crawled non-empty page; returning an error aborts the crawl. Callers must
    read the response payload from `content` because `resp.Body` is already
    consumed and closed.
-   **`PageInfo` and `CrawlStats`**: `PageInfo` carries the crawled `URL` and
    link-chain `Depth` (`0` for seed URLs) passed to `PageCallback`, while
    `CrawlStats` reports `TotalPagesCrawled` (unique normalized URLs visited
    during the run).
-   **`DefaultClientConfig`**: Returns an `*HttpCrawlerClientConfig` initialized
    with `http.DefaultForbiddenPathPatterns()` and proto defaults
    (`max_concurrency=1`, `max_page_size_bytes=1048576`, `max_depth=1`,
    `max_requests=100`, `scope_policy=SCOPE_POLICY_EXPAND`).
-   **`HttpCrawlerClientConfig`**: Protobuf client configuration
    (`httpcrawler_client_config_go_proto`) specifying concurrency, page size,
    depth, and client-wide request limits alongside regex `exclusions`, `Scope`
    entries (`domain` and slash-terminated `path`), and `ScopePolicy`
    (`SCOPE_POLICY_CONFIG_ONLY` or `SCOPE_POLICY_EXPAND`).
-   **`ErrNoCallback`, `ErrCrawlRequest`, `ErrReadResponseBody`**: Sentinel
    errors returned when `Crawl` is called with a `nil` callback, when
    initializing the HTTP client or building or executing an HTTP request fails,
    or when reading a response body fails unexpectedly.

## Usage

```go
import (
    "context"
    "net/http"

    "github.com/google/goonami-scanner/common/clients/httpcrawler"
    "github.com/google/goonami-scanner/core/config"
)

func crawlSeed(
    ctx context.Context,
    cfg *config.Config,
    seedURL string,
) (*httpcrawler.CrawlStats, error) {
    crawler := httpcrawler.NewSimpleCrawler(ctx, cfg)
    cb := func(
        ctx context.Context,
        info *httpcrawler.PageInfo,
        resp *http.Response,
        content []byte,
    ) error {
        // Inspect info.URL, info.Depth, resp.StatusCode, and content.
        return nil
    }
    return crawler.Crawl(ctx, cb, []string{seedURL})
}
```
