# Package `cve2026119618`

Package `cve2026119618` provides a Goonami vulnerability detector
(`dt/cve2026119618`) that identifies Apache HTTP Server instances (`2.4.55`
through `2.4.70`, and standalone `mod_h2` `2.0.8` through `2.0.42`) vulnerable
to the `mod_http2` `assign_headers()` race condition and heap memory corruption
RCE vulnerability (`CVE-2026-119618`), which has proven exploitability allowing
unlimited crash-tolerant attempts across Apache workers to probe and align heap
state and pivot RIP to ROP gadgets in `libc` or `httpd`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026119618"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the vulnerability advisory metadata
    (`GOOGLE` / `CVE-2026-119618`, related `CVE-2026-119618`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` /
    `(*Module).Detect(ctx context.Context, service *nspb.NetworkService)`**:
    Executes a non-destructive 3-stream sequential HTTP/2 (`h2` TLS ALPN and
    cleartext `h2c` prior knowledge) `TRACE` causal-ablation check (`<10`
    headers per stream, zero concurrency) verifying whether `assign_headers()`
    omits synthesized `Content-Length: 0` from `r->headers_in` on body-less
    `Content-Type` requests while preserving explicit `Content-Length: 0` on
    Stream 3 and enforcing Apache `ap_send_http_trace` request-body semantics on
    Stream 5.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve2026119618"
)
```
