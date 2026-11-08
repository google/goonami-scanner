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
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `OPENSSH_MUSL_PASSWORD_AUTH_BYPASS`, `CVE-2026-123158`,
    `Severity_CRITICAL`) supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Scopes probing to non-web, non-TLS TCP OpenSSH
    services (`"ssh"`, `"unknown"`, empty, or standard and fleet-observed SSH
    ports `22, 26, 222, 1022, 2022, 2222, 3389` when Nmap reports `"tcpwrapped"`
    or static port-table names without software identification), requires an
    `SSH-2.0-OpenSSH` server banner, iterates across candidate accounts (`root`,
    `alpine`, `sshuser`, `admin`, `user`, `guest`), retries genuine pre-banner
    connection drops across the OpenSSH 9.8+ `PerSourcePenalties` cooldown
    window, and verifies whether authentication succeeds with two distinct
    512-byte passwords while rejecting a short (`<= 256` bytes) invalid
    password. When verified, returns a `*dpb.DetectionReportList` with
    `DetectionStatus_VULNERABILITY_VERIFIED` and `Severity_CRITICAL`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/opensshauthbypass"
)
```
