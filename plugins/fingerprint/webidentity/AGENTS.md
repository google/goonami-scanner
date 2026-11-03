# Package `webidentity`

Package `webidentity` implements the `fp/webidentity` fingerprinter plugin,
which identifies web applications and their versions running on HTTP network
services in Goonami. During fingerprinting, it crawls target web services,
hashes HTTP responses, matches them against `.binproto` signature files loaded
into an in-memory hash registry, and optionally saves crawled HTML artifacts to
disk. It enriches identified `NetworkService` protos with software names,
narrowed version sets, application roots, and `CONTENT_TYPE_HASH` crawl results,
splitting into multiple service entries when distinct applications or
endpoint-specific responses are detected.

## Services

-   **`Module`**: Implements `module.Fingerprinter` (embedding
    `*module.BaseModule`) to identify web applications running on HTTP services,
    and automatically registers itself under `"fp/webidentity"` on package
    initialization.
-   **`New(ctx, config)`**: Validates `WebIdentityFpConfig` from
    `config.PluginsConfig().GetWebidentity()`, loads all `.binproto` signature
    files from `signatures_directory` into an in-memory `hash.Registry`, and
    returns a configured `module.Fingerprinter`.
-   **`(*Module).Fingerprint(ctx, service)`**: Crawls web services from their
    web root (returning non-web services unchanged), hashes responses into
    `CONTENT_TYPE_HASH` crawl results, optionally writes HTML bodies to the
    module artifacts directory within configured per-file and total byte
    budgets, and reconciles results across split hostname and IP endpoints.
    Returns one `NetworkService` per matched software root (populated with
    `Software`, intersected `VersionSet`, `ApplicationRoot`, and matching
    `CrawlResults`) plus an additional service entry for any remaining
    unidentified crawl results.
-   **Sentinel errors (`ErrNoFingerprintsDirectory`, `ErrSignaturesRead`,
    `ErrSignaturesUnmarshal`, `ErrArtifactsWrite`)**:
    `ErrNoFingerprintsDirectory`, `ErrSignaturesRead`, and
    `ErrSignaturesUnmarshal` report missing `signatures_directory` configuration
    or signature file read and unmarshal failures in `New`. `ErrArtifactsWrite`
    reports filesystem failures when resolving the module artifacts directory or
    writing crawled HTML response files during `Fingerprint`.
-   **`WebIdentityFpConfig` (`webidentity_fp_config_go_proto`)**: Plugin
    configuration protobuf specifying the required `signatures_directory` path
    along with optional HTML artifact persistence (`write_html_to_file`,
    defaulting to `false`) and size caps (`maximum_file_size_bytes` at 1 MiB and
    `maximum_storage_space_bytes` at 100 MiB).
-   **`Fingerprints` and signature messages (`fingerprints_go_proto`)**: Defines
    the protobuf schema (`Fingerprints`, `SoftwareIdentity`, `ContentHash`,
    `HashVersion`, `PathVersion`, `Hash`, and `Version`) for `.binproto`
    signature files that map URL paths and response hex hashes to software names
    and candidate versions.

## Usage

```go
import (
  // Registers the "fp/webidentity" fingerprinter with core/module.
  _ "github.com/google/goonami-scanner/plugins/fingerprint/webidentity"
)
```

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/plugins/fingerprint/webidentity"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

func identifyService(
    ctx context.Context,
    cfg *config.Config,
    service *nspb.NetworkService,
) ([]*nspb.NetworkService, error) {
  fp, err := webidentity.New(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return fp.Fingerprint(ctx, service)
}
```
