# Package `php2shell`

Package `php2shell` provides a Goonami vulnerability detector (`dt/php2shell`)
that identifies PHP web services vulnerable to PHP2Shell (`CVE-2026-109618` and
`CVE-2026-109619`) via a zero-side-effect `PHP Request Startup` session-flush
differential and causal-ablation control.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/php2shell"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `CVE-2026-109618`, related `CVE-2026-109618` and
    `CVE-2026-109619`, `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Probes web services with an invalid, overlong
    session ID (>250 bytes, failing `mod_files` validation and exceeding
    `memcached`'s 250-byte key limit; `redis` emits startup initialization
    warnings only when `s_open` or `s_read` fails on an unreachable or
    misconfigured backend) and `PHP_SESSION_UPLOAD_PROGRESS` to check if
    `php_session_rfc1867_update()` / `php_session_rfc1867_cleanup()` ignores
    `php_session_initialize() == FAILURE` and invokes `php_session_flush(1)`,
    then verifies that the startup write warning disappears when
    `PHP_SESSION_UPLOAD_PROGRESS` is omitted.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/php2shell"
)
```
