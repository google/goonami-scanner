# Package `redisunauthrce`

Package `redisunauthrce` provides a Goonami vulnerability detector
(`dt/redisunauthrce`) that identifies unauthenticated Redis instances permitting
command execution over the Redis Serialization Protocol (RESP).

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/redisunauthrce"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module` configured with the per-request
    timeout from `cfg`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `REDIS_UNAUTHENTICATED_COMMAND_EXECUTION`, `Severity_CRITICAL`).
-   **`(*Module).Detect(ctx context.Context, service *nspb.NetworkService)`**:
    Skips web and non-TCP services, connects over TCP or TLS depending on
    `netservice.HasTLS(service)`, verifies structured `INFO server` output,
    validates that an unknown command returns a RESP error reply, and confirms
    active command execution via zero-side-effect Lua arithmetic (`EVAL`) or
    administrative/keyspace fallbacks (`CONFIG GET dir`, `DBSIZE` + `ROLE`).

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/redisunauthrce"
)
```
