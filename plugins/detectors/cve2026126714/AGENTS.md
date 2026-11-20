# Package `cve2026126714`

Package `cve2026126714` provides a Goonami vulnerability detector
(`dt/cve2026126714`) that identifies PHP web services vulnerable to
`CVE-2026-126714` (`phpAfterShell`), a partial session-file overwrite flaw in
PHP's default `files` session save handler (`ext/session/mod_files.c`), using a
zero-side-effect `PHP Request Startup` behavioral differential and
causal-ablation control.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/cve2026126714"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `CVE-2026-126714`, related `CVE` / `CVE-2026-126714`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Probes web services with an illegal, overlong
    session ID (>250 bytes, rejected by `ps_files_valid_key` prior to opening or
    creating any session file) alongside `PHP_SESSION_UPLOAD_PROGRESS` to check
    whether `session.upload_progress` startup initialization executes against
    the `files` session save handler, then verifies via a causal-ablation
    control request (omitting `PHP_SESSION_UPLOAD_PROGRESS`) that the startup
    `files` read warning disappears.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/cve2026126714"
)
```
