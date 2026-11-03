# Package `netservice`

Package `netservice` provides helper functions for inspecting, addressing, and
managing web crawl state on Tsunami `*nspb.NetworkService` protobuf messages in
Goonami. It determines whether a target service supports SSL/TLS or HTTP, and
builds `http://` or `https://` base URLs from the service's `NetworkEndpoint`
for HTTP clients, LLM tools, and templated detectors. It also appends and
queries `*wcpb.CrawlResult` entries stored in the service's `WebServiceContext`,
resolving relative or absolute URIs against the primary web root.

## Services

-   **`HasTLS` and `IsWebService`**: `HasTLS(service *nspb.NetworkService) bool`
    reports whether `service` lists any `SupportedSslVersions`, and
    `IsWebService(service *nspb.NetworkService) bool` reports whether `service`
    lists any `SupportedHttpMethods`.
-   **`BuildWebRoot` and `BuildAllWebRoots`**:
    `BuildAllWebRoots(service *nspb.NetworkService) ([]string, error)` formats
    `http://` or `https://` base URLs (chosen via `HasTLS`) from
    `netendpoint.ToURIAuthorities(service.GetNetworkEndpoint())`, ordering
    hostname-based URLs ahead of IP-based URLs and propagating errors such as
    `netendpoint.ErrEndpointMissingAddress`.
    `BuildWebRoot(service *nspb.NetworkService) (string, error)` returns the
    first URL from `BuildAllWebRoots` without a trailing slash, prioritizing the
    hostname so HTTP virtual-host matching succeeds.
-   **`AddCrawlResults`**: `AddCrawlResults(service *nspb.NetworkService,
    crawlResults []*wcpb.CrawlResult)` appends `crawlResults` to `service`'s
    `WebServiceContext.CrawlResults` in place, initializing `ServiceContext` and
    `WebServiceContext` when missing. When `WebServiceContext` is unset, it
    replaces `ServiceContext` with a newly built message containing
    `WebServiceContext`.
-   **`GetCrawlContent` and `WasCrawled`**: `GetCrawlContent(service
    *nspb.NetworkService, uri string) ([]byte, wcpb.CrawlContentType, bool)`
    resolves relative or absolute `uri` values against `BuildWebRoot(service)`
    and returns the first matching `CrawlResult` content, `CrawlContentType`,
    and `true`, or
    `(nil, wcpb.CrawlContentType_CONTENT_TYPE_UNSPECIFIED, false)` when
    unresolved or absent.
    `WasCrawled(service *nspb.NetworkService, uri string) bool` wraps
    `GetCrawlContent` to report whether the resolved `uri` appears in
    `service`'s crawl results.

## Usage

```go
import (
  "fmt"

  "github.com/google/goonami-scanner/core/net/netservice"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
  wcpb "github.com/google/tsunami-security-scanner/proto/go/web_crawl_go_proto"
)

func recordAndReadPage(
    service *nspb.NetworkService,
    payload []byte,
) ([]byte, error) {
  if !netservice.IsWebService(service) {
    return nil, fmt.Errorf("target is not an HTTP web service")
  }

  webRoot, err := netservice.BuildWebRoot(service)
  if err != nil {
    return nil, err
  }

  targetURL := webRoot + "/login"
  result := wcpb.CrawlResult_builder{
    CrawlTarget:      wcpb.CrawlTarget_builder{Url: targetURL}.Build(),
    Content:          payload,
    CrawlContentType: wcpb.CrawlContentType_CONTENT_TYPE_RAW,
  }.Build()
  netservice.AddCrawlResults(service, []*wcpb.CrawlResult{result})

  if body, _, ok := netservice.GetCrawlContent(service, "/login"); ok {
    return body, nil
  }
  return nil, nil
}
```
