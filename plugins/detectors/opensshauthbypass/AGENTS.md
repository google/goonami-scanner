# Package `opensshauthbypass`

Package `opensshauthbypass` provides a Goonami vulnerability detector
(`dt/opensshauthbypass`) that identifies OpenSSH servers linked against `musl`
libc (such as on Alpine Linux, OpenWrt, Buildroot, and Yocto) that are
vulnerable to password authentication bypass via `crypt()` returning `"*"` on
passwords exceeding 256 bytes.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/opensshauthbypass"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` backed by `sshclient.New(cfg)`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `OPENSSH_MUSL_PASSWORD_AUTH_BYPASS`, `CVE-2026-123158`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips web, TLS, and non-TCP services, verifies an
    `SSH-2.0-OpenSSH` server banner on any port with bounded cooldown retries
    when OpenSSH 9.8+ `PerSourcePenalties` drops subsequent connections after
    initial banner confirmation, aborts early when password authentication is
    disabled, and tests candidate accounts (`root`, `alpine`, `sshuser`,
    `admin`, `user`, `guest`) using two distinct 300-byte passwords paired with
    a `<= 256`-byte negative control. When verified, returns a
    `*dpb.DetectionReportList` with `DetectionStatus_VULNERABILITY_VERIFIED` and
    `Severity_CRITICAL`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/opensshauthbypass"
)
```
