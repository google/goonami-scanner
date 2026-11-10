# Package `cve202682329`

Package `cve202682329` provides a Goonami vulnerability detector
(`dt/artifactory_cve_2026_82329`) that identifies JFrog Artifactory instances
(bundled JFrog Access service) vulnerable to CVE-2026-82329.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/artifactory_cve_2026_82329"` via
    `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` configured with `cfg`.
-   **`(*Module).Advisories`**: Returns the static vulnerability advisory
    (`TSUNAMI_COMMUNITY` / `CVE_2026_82329`, `CVE-2026-82329`,
    `Severity_CRITICAL`) reported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Probes `/access/api/v1/registry/join` and
    `/artifactory/access/api/v1/registry/join` on candidate HTTP/Artifactory TCP
    services using a non-destructive `skip_node_registration` join request,
    verifies that the response issues a signed administrative JWT bound to the
    probe `service_id`, and confirms that an unrecognized key identifier is
    rejected before returning a `DetectionStatus_VULNERABILITY_VERIFIED` report.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/artifactory/cve202682329"
)
```
