# Package `fakerunner`

Package `fakerunner` provides an in-memory test fake implementing the
`runner.Runner` interface for Goonami unit tests. By default, it records
registered port scanners, fingerprinters, and vulnerability detectors in memory
for inspection and returns `(nil, nil)` when executing a scan. Callers such as
`entrypoint` tests inject `FakeRunner` to verify module registration and stub
custom scan results or errors via per-method callback overrides.

## Services

-   **`FakeRunner` and `New`**: In-memory test double implementing
    `runner.Runner` with module introspection and per-method callback hooks.
    `New()` returns an empty `*FakeRunner` ready for module registration and
    scan execution.
-   **`RegisterPortScanner`, `RegisterFingerprinter`, and `RegisterDetector`**:
    Implement `runner.Runner` module registration by storing the latest
    `module.PortScanner` and appending `module.Fingerprinter` and
    `module.VulnDetector` instances. When a corresponding override callback is
    set, registration delegates directly to that callback without recording the
    module on `FakeRunner`.
-   **`PortScanner`, `Fingerprinters`, and `Detectors`**: Introspection getters
    returning the registered `module.PortScanner`, `[]module.Fingerprinter`, and
    `[]module.VulnDetector` recorded by the runner.
-   **`Run` and `OverrideRun` (`OverrideRunFn`)**: `Run(ctx, target)` delegates
    to the `OverrideRunFn` callback configured via `OverrideRun`, or returns
    `(nil, nil)` when no override is set. Use `OverrideRun` to return canned
    `*ScanResults` protos or simulate scan execution failures.
-   **`OverrideRegisterPortScanner`, `OverrideRegisterFingerprinter`, and
    `OverrideRegisterDetector`**: Configure `OverrideRegisterPortScannerFn`,
    `OverrideRegisterFingerprinterFn`, or `OverrideRegisterDetectorFn` callbacks
    to intercept registration calls and inject custom logic or errors.

## Usage

```go
import (
    "context"

    "github.com/google/goonami-scanner/common/testfakes/fakerunner"
    "github.com/google/goonami-scanner/core/entrypoint"
    srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

runner := fakerunner.New()
runner.OverrideRun(func(
    ctx context.Context, target string,
) (*srpb.ScanResults, error) {
    return srpb.ScanResults_builder{
        ScanStatus: srpb.ScanStatus_SUCCEEDED,
    }.Build(), nil
})

ep, err := entrypoint.New(ctx, &entrypoint.Options{
    Config: cfg,
    Runner: runner,
})
if err != nil {
    return err
}

// Inspect modules registered during entrypoint initialization.
ps := runner.PortScanner()
fps := runner.Fingerprinters()
dets := runner.Detectors()
_, _, _ = ps, fps, dets

results, err := ep.Run(ctx, "192.0.2.1")
```
