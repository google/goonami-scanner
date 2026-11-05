# Package `opensshauthbypass`

Package `opensshauthbypass` provides a Goonami vulnerability detector
(`dt/opensshauthbypass`) that identifies OpenSSH servers linked against `musl`
libc (such as on Alpine Linux) that are vulnerable to password authentication
bypass via `crypt()` returning `"*"` on passwords exceeding 256 bytes.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/opensshauthbypass"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` backed by `sshclient.New(cfg)`.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips web and non-TCP services, resolves the
    endpoint authority, and verifies whether `root` authentication succeeds with
    two distinct 512-byte passwords while rejecting a short (`<= 256` bytes)
    invalid password. When verified, returns a `*dpb.DetectionReportList` with
    `DetectionStatus_VULNERABILITY_VERIFIED` and `Severity_CRITICAL`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/opensshauthbypass"
)
```
