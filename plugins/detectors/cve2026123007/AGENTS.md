# Package `cve2026123007`

Package `cve2026123007` provides a Goonami vulnerability detector
(`dt/cve2026123007`) that identifies NGINX Open Source (`1.9.5` through `1.30.6`
and `1.31.0` through `1.31.8`) and unpatched NGINX Plus or distribution builds
vulnerable to the HTTP/2 queued-frame flow-control window validation bypass and
heap buffer overflow (`CVE-2026-123007`).

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026123007"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` honoring `cfg.TimeoutPerRequest()`.
-   **`(*Module).Advisories`**: Returns the vulnerability advisory metadata
    (`GOOGLE` / `CVE-2026-123007`, related `CVE-2026-123007`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` /
    `(*Module).Detect(ctx context.Context, service *nspb.NetworkService)`**:
    Verifies NGINX `ngx_http_v2` HTTP/2 termination (`18`-byte or `24`-byte
    initial `SETTINGS` frame plus Stream `0` `WINDOW_UPDATE` increment
    `2147418112`) over TLS ALPN `h2` or cleartext `h2c` prior knowledge and
    executes a non-destructive Stream `0` queued-frame `WINDOW_UPDATE` boundary
    check without sending `RST_STREAM`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve2026123007"
)
```
