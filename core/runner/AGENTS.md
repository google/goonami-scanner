# Package `runner`

Package `runner` defines the core orchestration interface for registering and
executing Goonami scan modules. It decouples high-level engine setup (such as
`entrypoint`) from concrete scan execution workflows. Implementations register
port scanners, service fingerprinters, and vulnerability detectors before
running a scan against a target and returning Tsunami `ScanResults`.

## Services

-   **`Runner`**: Orchestrator interface defining how Goonami scan modules are
    registered and executed.
-   **`Runner.RegisterPortScanner`**:
    `RegisterPortScanner(context.Context, module.PortScanner) error` registers a
    port scanner module with the orchestrator.
-   **`Runner.RegisterFingerprinter`**:
    `RegisterFingerprinter(context.Context, module.Fingerprinter) error`
    registers a service fingerprinter module with the orchestrator.
-   **`Runner.RegisterDetector`**:
    `RegisterDetector(context.Context, module.VulnDetector) error` registers a
    vulnerability detector module with the orchestrator.
-   **`Runner.Run`**: `Run(context.Context, string) (*srpb.ScanResults, error)`
    executes the scan workflow against the given target string and returns the
    Tsunami scan results report.

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/core/module"
    "github.com/google/goonami-scanner/core/runner"

    srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

func executeScan(
    ctx context.Context,
    r runner.Runner,
    ps module.PortScanner,
    fps []module.Fingerprinter,
    dts []module.VulnDetector,
    target string,
) (*srpb.ScanResults, error) {
    if err := r.RegisterPortScanner(ctx, ps); err != nil {
        return nil, err
    }
    for _, fp := range fps {
        if err := r.RegisterFingerprinter(ctx, fp); err != nil {
            return nil, err
        }
    }
    for _, dt := range dts {
        if err := r.RegisterDetector(ctx, dt); err != nil {
            return nil, err
        }
    }
    return r.Run(ctx, target)
}
```
