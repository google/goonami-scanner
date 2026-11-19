# Package `cve202144228`

Package `cve202144228` provides a Goonami vulnerability detector
(`dt/cve202144228`) that identifies web services vulnerable to Apache Log4j2
JNDI remote code execution (`CVE-2021-44228` and the `2.15.0` incomplete fix
`CVE-2021-45046`) via verified out-of-band callback server interactions.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve202144228"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` configured with the scanner's global
    HTTP and callback server settings.
-   **`(*Module).Advisories`**: Returns the static vulnerability advisory
    (`GOOGLE` / `CVE_2021_44228`, related `CVE` / `CVE-2021-44228`,
    `Severity_CRITICAL`) reported by this detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips non-web services and scans when the callback
    server is disabled, verifies HTTP reachability on the target web root, and
    injects unique per-service JNDI callback expressions (`ldap://`,
    `ldap://127.0.0.1#.` authority-fragment bypass, and `dns://`) across
    commonly logged HTTP headers, root and 404 paths, crawled URL query
    parameters, POST form bodies, and servlet endpoints. Polls the callback
    server for out-of-band DNS or HTTP interactions matching the cryptographic
    secret and returns `DetectionStatus_VULNERABILITY_VERIFIED` only when a
    callback interaction is confirmed.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve202144228"
)
```
