# Package `rdp`

Package `rdp` provides a Goonami weak-credentials and blank-password
vulnerability detector (`dt/wk/rdp`) that tests Remote Desktop Protocol (RDP)
services using `common/bruteforce` and `common/clients/rdpclient`.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/wk/rdp"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new RDP weak-credentials detector backed by
    `bruteforce.New`, `rdpclient.New(cfg)`, and the curated `DefaultCredentials`
    credential store (including empty passwords for each common RDP account).
-   **`NewWithOptions(ctx context.Context, cfg *config.Config, opts
    *bruteforce.Options) (*bruteforce.Detector, error)`**: Constructs an RDP
    weak-credentials detector with custom `bruteforce.Options`.
-   **`DefaultCredentials()`**: Returns the ordered list of curated RDP default
    and empty-password credential pairs.
-   **`Handler` and `NewHandler(cfg *config.Config)`**: Implements
    `bruteforce.Handler` and spawns sequential `bruteforce.Worker` instances
    that fingerprint candidate TCP RDP services via negative-canary probing,
    skip web services and interactive-login greeters without false positives,
    and skip locked or disabled accounts upon receiving corresponding NTSTATUS
    codes.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/weakcreds/rdp"
)
```
