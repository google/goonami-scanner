# Package `simplerunner`

Package `simplerunner` provides Goonami's default `runner.Runner` implementation
for orchestrating scan modules against a target. It executes a three-phase
pipeline—port scanning, service fingerprinting, and vulnerability detection—with
bounded service-level concurrency configured via `*config.Config`. Non-fatal
fingerprinter and detector errors degrade the scan status to
`PARTIALLY_SUCCEEDED` without aborting remaining modules, while phase, module,
and finding metrics are recorded automatically.

## Services

-   **`SimpleRunner`**: Default `runner.Runner` orchestrator holding the scan
    `*config.Config`, a single `module.PortScanner`, and ordered slices of
    `module.Fingerprinter` and `module.VulnDetector` modules.
-   **`New(config)`**: Creates a `*SimpleRunner` backed by `config` (reading
    `GlobalConfig().GetPerformance().GetMaxConcurrency()` for service-level
    parallelism), or returns `ErrConfigNil` if `config` is nil.
-   **`(*SimpleRunner).RegisterPortScanner(ctx, module)`**: Registers the single
    `module.PortScanner` for the runner, returning
    `ErrPortScannerAlreadyRegistered` if one is already set or
    `ErrRegistrationNil` if `module` is nil.
-   **`(*SimpleRunner).RegisterFingerprinter(ctx, module)` /
    `(*SimpleRunner).RegisterDetector(ctx, module)`**: Append a
    `module.Fingerprinter` or `module.VulnDetector` in execution order,
    returning `ErrRegistrationNil` if `module` is nil.
-   **`(*SimpleRunner).PortScanStep(ctx, target)`**: Runs the registered port
    scanner against `target`, records module duration and error metrics, and
    returns `*rpb.PortScanningReport` (or `ErrNoPortScanner` if none is
    registered).
-   **`(*SimpleRunner).FingerprintStep(ctx, portscan)`**: Concurrently
    fingerprints cloned network services from `portscan` through all registered
    fingerprinters in order, accumulating split services into a
    `*rpb.FingerprintingReport` (or returning `portscan` services unchanged when
    no fingerprinters are registered). Services failing with
    `netendpoint.ErrEndpointMissingAddress` are dropped, whereas other module
    errors mark the scan degraded and pass the service to the next fingerprinter
    unless `ctx` is canceled.
-   **`(*SimpleRunner).DetectStep(ctx, fpreport)`**: Concurrently runs all
    registered detectors against cloned network services from `fpreport` and
    returns the combined `[]*dpb.DetectionReport` slice (or `nil` when no
    detectors are registered). Individual detector errors are logged, recorded
    in metrics, and mark the scan degraded without stopping remaining detectors
    unless `ctx` is canceled.
-   **`(*SimpleRunner).Run(ctx, target)`**: Executes `PortScanStep`,
    `FingerprintStep`, and `DetectStep` sequentially, records phase and scan
    metrics, and builds `*srpb.ScanResults`. It populates `ScanFindings` only
    from detections with status `VULNERABILITY_PRESENT` or
    `VULNERABILITY_VERIFIED` (retaining all reports in `FullDetectionReports`)
    and sets `ScanStatus` to `PARTIALLY_SUCCEEDED` if any fingerprinter or
    detector failed, or `SUCCEEDED` otherwise.
-   **Sentinel Errors**: Exports `ErrConfigNil` (nil config passed to `New`),
    `ErrRegistrationNil` (nil module passed to a `Register*` method),
    `ErrPortScannerAlreadyRegistered` (duplicate `RegisterPortScanner` call),
    and `ErrNoPortScanner` (running a scan without a port scanner).

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/core/config"
    "github.com/google/goonami-scanner/core/module"
    "github.com/google/goonami-scanner/core/runner/simplerunner"

    srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

func runCustomScan(
    ctx context.Context,
    cfg *config.Config,
    target string,
    scanner module.PortScanner,
    fingerprinters []module.Fingerprinter,
    detectors []module.VulnDetector,
) (*srpb.ScanResults, error) {
    r, err := simplerunner.New(cfg)
    if err != nil {
        return nil, err
    }
    if err := r.RegisterPortScanner(ctx, scanner); err != nil {
        return nil, err
    }
    for _, fp := range fingerprinters {
        if err := r.RegisterFingerprinter(ctx, fp); err != nil {
            return nil, err
        }
    }
    for _, dt := range detectors {
        if err := r.RegisterDetector(ctx, dt); err != nil {
            return nil, err
        }
    }
    return r.Run(ctx, target)
}
```
