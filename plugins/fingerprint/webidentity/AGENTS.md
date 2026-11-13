# Package `webidentity`

Package `webidentity` implements the `fp/webidentity` fingerprinter plugin,
which identifies web applications and their versions running on HTTP network
services in Goonami. It crawls target web services, populates an in-memory HTTP
cache, evaluates declarative `.textproto` workflows using the two-pass engine,
and optionally persists crawled HTML artifacts to disk. It enriches identified
`NetworkService` protos with software names, normalized `VersionSet` entries,
application roots, and `CONTENT_TYPE_HASH` crawl results.

## Services

-   **`Module`**: Implements `module.Fingerprinter` (embedding
    `*module.BaseModule`) and automatically registers itself under
    `"fp/webidentity"` on package initialization.
-   **`New(ctx, config)`**: Reads `WebIdentityFpConfig` from
    `config.PluginsConfig().GetWebidentity()`, loads `.textproto`
    `WebFingerprint` definitions from `signatures_directory` (or the embedded
    catalog when `signatures_directory` is empty), and initializes an
    `engine.Engine`.
-   **`(*Module).Fingerprint(ctx, service)`**: Returns non-web services
    unchanged, splits endpoints that carry both hostname and IP addresses,
    creates a per-service `SimpleCrawler` and `cache.Cache`, runs passive and
    active declarative workflows, records crawl hashes and optional HTML
    artifacts, reconciles identical endpoint results, and records
    `metrics.FingerprintIdentifications` per reconciled `(fingerprint, rule)`.
-   **Sentinel errors (`ErrSignaturesRead`, `ErrSignaturesUnmarshal`,
    `ErrArtifactsWrite`)**: Report signature loading/unmarshaling failures in
    `New` and artifact persistence failures during `Fingerprint`.
-   **`WebIdentityFpConfig` (`webidentity_fp_config_go_proto`)**: Plugin
    configuration protobuf specifying optional `signatures_directory` override,
    `write_html_to_file` (default `false`), `maximum_file_size_bytes` (1 MiB),
    and `maximum_storage_space_bytes` (100 MiB).
-   **`WebFingerprint` (`fingerprint_go_proto`) and `WebFingerprintTests`
    (`fingerprint_test_go_proto`)**: Declarative workflow schema and hermetic
    test suite protobuf definitions.

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
