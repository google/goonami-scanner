# Package `redisunauth`

Package `redisunauth` provides a Goonami vulnerability detector
(`dt/redisunauth`) that identifies unauthenticated Redis, Valkey, and
RESP2-compatible services over TCP/TLS and distinguishes unauthenticated
database read/write access (`HIGH`) from live server configurations permitting
direct OS command execution (`CRITICAL`).

## Services

-   **`ModuleName`**: Registered detector identifier (`"dt/redisunauth"`).
-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/redisunauth"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the two static base advisories
    supported by the detector:
    -   `GOOGLE` / `REDIS_UNAUTHENTICATED_COMMAND_EXECUTION`
        (`Severity_CRITICAL`)
    -   `GOOGLE` / `REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS`
        (`Severity_HIGH`)
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Skips web and non-TCP services, verifies a
    bounded RESP2 Bulk String reply to `INFO server` containing a numeric
    engine version, checks runtime RCE misconfigurations via non-destructive
    `CONFIG GET`, path-rejected `CONFIG SET dbfilename "a/b"` on native Redis
    `>= 3.2` and Valkey (or synthetic `CONFIG SET __tsunami_ro_probe__ ""` on
    legacy Redis `< 3.2`), and syntax-rejected `MODULE LOADEX "" CONFIG` /
    nonexistent `MODULE UNLOAD` probes, and emits
    `DetectionStatus_VULNERABILITY_VERIFIED`.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/redisunauth"
)
```
