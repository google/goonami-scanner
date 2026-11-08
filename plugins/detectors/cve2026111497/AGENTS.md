# Package `cve2026111497`

Package `cve2026111497` provides a Goonami vulnerability detector
(`dt/cve2026111497`) for CVE-2026-111497 (Google Brotli Decoder 25-bit
`block_length_2` bit-field truncation out-of-bounds write remote code
execution).

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026111497"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `CVE-2026-111497`, related `CVE` / `CVE-2026-111497`,
    `Severity_CRITICAL`) supported by the detector.
-   **`(*Module).Detect(ctx context.Context, service *nspb.NetworkService)`**:
    Verifies whether the target web service automatically decompresses
    `Content-Encoding: br` request bodies using an unpatched Google Brotli
    decoder (versions `1.0.3` through `1.0.9`, `1.1.0`, or `1.2.0`) via a
    5-step zero-side-effect differential decompression protocol.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve2026111497"
)
```
