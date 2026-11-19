# Package `cve2026111497outbound`

Package `cve2026111497outbound` provides a Goonami vulnerability detector
(`dt/cve2026111497outbound`) that identifies web applications and CMSs
vulnerable to unauthenticated Remote Code Execution via CVE-2026-111497 (an
out-of-bounds write in the Google Brotli decompression library `libbrotlidec`
`1.0.3` through `1.2.0`) triggered when an unauthenticated endpoint fetches an
attacker-supplied URL and automatically decompresses `Content-Encoding: br` HTTP
responses.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026111497outbound"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config)`**:
    Constructs a new `*Module` returning `(module.VulnDetector, error)`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `CVE-2026-111497-OUTBOUND`, `Severity_CRITICAL`) supported by
    the detector.
-   **`(*Module).Detect(ctx context.Context, service *nspb.NetworkService)`**:
    Evaluates web services against both Multi-CMS XML-RPC `pingback.ping`
    (WordPress, Drupal, b2evolution, Serendipity, DokuWiki, Movable Type,
    TikiWiki) and Next.js Image Optimizer (`/_next/image`) endpoints using a
    zero-side-effect 4-step differential decompression protocol with the Tsunami
    Callback Server (`brotli_valid`, `brotli_invalid`, and
    `brotli_cve_2026_111497` presets). When the target decompresses the stream
    identically to valid Brotli without triggering fallback retries, returns a
    `*dpb.DetectionReportList` with `DetectionStatus_VULNERABILITY_VERIFIED`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve2026111497outbound"
)
```
