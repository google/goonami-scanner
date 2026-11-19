# Package `daskunauthrce`

Package `daskunauthrce` provides a Goonami vulnerability detector
(`dt/daskunauthrce`) that identifies exposed unauthenticated Dask Distributed
and NVIDIA RAPIDS (`dask-cuda`) cluster endpoints allowing remote code
execution.

## Services

-   **`init` (Plugin Registration)**: Blank-importing the package registers the
    detector under `"dt/daskunauthrce"` via `module.RegisterDetector`.
-   **`New(ctx context.Context, cfg *config.Config) (module.VulnDetector,
    error)`**: Constructs a new `*Module`.
-   **`(*Module).Advisories`**: Returns the static base vulnerability advisory
    (`GOOGLE` / `DASK_DISTRIBUTED_UNAUTHENTICATED_RCE`, `Severity_CRITICAL`)
    supported by the detector.
-   **`Module` / `(*Module).Detect(ctx context.Context, service
    *nspb.NetworkService)`**: Probes TCP services for Dask Comm endpoints over
    raw TCP/TLS (`!netservice.IsWebService(service)`) and WebSocket (`ws://` /
    `wss://` when `netservice.IsWebService(service)`), using
    `netservice.HasTLS(service)`, `netendpoint.ToURIAuthority`, and
    `cfg.TimeoutPerRequest()`. Performs a 3-step binary MsgPack/Pickle Comm
    verification (handshake, `identity` daemon check across `Scheduler`,
    `Worker`, `CUDAWorker`, and `Nanny`, and non-destructive `operator.add(a,
    b)` evaluation on random 8-digit integers via `run_function`, worker/nanny
    `broadcast`, or `run`) and returns a `*dpb.DetectionReportList` with
    `DetectionStatus_VULNERABILITY_VERIFIED` when server-computed execution
    succeeds without authentication.

## Usage

Blank-import the package to register the detector in a Goonami binary:

```go
import (
    _ "github.com/google/goonami-scanner/plugins/detectors/daskunauthrce"
)
```
