# Package `scope`

Package `scope` defines domain and directory-prefix boundaries used by Goonami's
HTTP crawler (`common/clients/httpcrawler`) to restrict which discovered URLs
are crawled. It constructs normalized crawl scopes from
`HttpCrawlerClientConfig` protobuf configurations and initial seed URLs
according to the configured scope policy. During a crawl run, candidate links
are evaluated against the active scopes to reject cross-domain or
out-of-directory targets before issuing HTTP requests.

## Services

-   **`Scope`**: Struct holding an allowed `Domain` (`hostname` or
    `hostname:port`) and a normalized directory `Path` prefix. Its
    `Decision(targetURL)` and `Matches(targetURL)` methods check whether a
    candidate URL matches the exact domain (including port) and path prefix.
-   **`Decision` (`DecisionUnknown`, `DecisionInScope`,
    `DecisionDomainMismatch`, `DecisionPathMismatch`)**: Enum returned by
    `Scope.Decision` describing whether a target URL is in scope or why it was
    rejected.
-   **`FromProto` and `FromURL`**: Construct a `*Scope` with a normalized `Path`
    from an `*HttpCrawlerClientConfig_Scope` protobuf message (`FromProto`) or a
    raw URL string (`FromURL`).
-   **`Load`**: Builds a `[]*Scope` slice from `HttpCrawlerClientConfig` scopes
    and, unless `ScopePolicy` is `SCOPE_POLICY_CONFIG_ONLY`, appends scopes
    derived via `FromURL` from the seed URLs.
-   **`MatchAnyScope`**: Reports whether a target URL matches at least one
    `*Scope` in a slice, returning early on the first match or URL parse error.
-   **`NormalizePath`**: Converts a URL path into a slash-terminated directory
    prefix, stripping any dot-containing file basename to its parent directory.
-   **`ErrParseURL`**: Sentinel error wrapped and returned when `url.Parse`
    fails in `FromURL`, `Load`, `Scope.Decision`, `Scope.Matches`, or
    `MatchAnyScope`.

## Usage

Load scopes for a crawl run and filter discovered links:

```go
import (
    "github.com/google/goonami-scanner/common/clients/httpcrawler/scope"

    cpb "github.com/google/goonami-scanner/common/clients/httpcrawler/httpcrawler_client_config_go_proto"
)

func filterInScope(
    cfg *cpb.HttpCrawlerClientConfig,
    seedURLs, links []string,
) ([]string, error) {
    scopes, err := scope.Load(cfg, seedURLs)
    if err != nil {
        return nil, err
    }

    var allowed []string
    for _, link := range links {
        ok, err := scope.MatchAnyScope(link, scopes)
        if err != nil {
            return nil, err
        }
        if ok {
            allowed = append(allowed, link)
        }
    }
    return allowed, nil
}
```

Inspect a detailed match decision against a single URL-derived scope:

```go
s, err := scope.FromURL("https://example.com:8443/app/index.html")
if err != nil {
    return err
}
// Normalized scope has Domain "example.com:8443" and Path "/app/".
decision, err := s.Decision("https://example.com:8443/admin/login")
if err != nil {
    return err
}
// decision == scope.DecisionPathMismatch
```
