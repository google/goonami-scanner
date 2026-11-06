# Package `fakemodule`

Package `fakemodule` provides configurable test doubles for Goonami's
`module.PortScanner`, `module.Fingerprinter`, and `module.VulnDetector`
interfaces. Each fake embeds `*module.BaseModule`, delegates execution to a
caller-supplied callback, and tracks invocation counts via `CountCalls()`. It is
used in runner and entrypoint tests to simulate module registration,
initialization errors, scan outputs, and runtime failures without network I/O.

## Services

-   **`FakePortScanner` (`NewFakePortScanner`, `InitFakePortScanner`)**:
    Non-concurrency-safe test double for `module.PortScanner` whose
    `Scan(ctx, target)` method increments `CountCalls()` and delegates to a
    `FakePortScanFn` callback. `InitFakePortScanner(name, err, override)`
    returns a `module.InitPortScannerFn` that yields `err` when non-nil or
    constructs the fake.
-   **`FakePortScanFn`, `FakePortScanFnDoNothing`, `FakePortScanFnErrors`,
    `ErrFakePortScanGeneric`**: Callback type
    `func(ctx context.Context, target string) (*rpb.PortScanningReport, error)`
    and canned helpers for `FakePortScanner`. `FakePortScanFnDoNothing` returns
    `(nil, nil)`, while `FakePortScanFnErrors` returns
    `(nil, ErrFakePortScanGeneric)`.
-   **`FakeFingerprinter` (`NewFakeFingerprinter`, `InitFakeFingerprinter`)**:
    Test double for `module.Fingerprinter` with mutex-guarded call counting
    whose `Fingerprint(ctx, svc)` method increments `CountCalls()` and delegates
    to a `FakeFingerprintFn` callback.
    `InitFakeFingerprinter(name, err, override)` returns a
    `module.InitFingerprinterFn` that yields `err` when non-nil or constructs
    the fake.
-   **`FakeFingerprintFn`, `FakeFingerprintFnDoNothing`,
    `FakeFingerprintFnErrors`, `ErrFakeFingerprintGeneric`**: Callback type
    `func(ctx context.Context, svc *nspb.NetworkService)
    ([]*nspb.NetworkService, error)` and canned helpers for `FakeFingerprinter`.
    `FakeFingerprintFnDoNothing` returns `([]*nspb.NetworkService{svc}, nil)`,
    while `FakeFingerprintFnErrors` returns `(nil, ErrFakeFingerprintGeneric)`.
-   **`FakeVulnDetector` (`NewFakeVulnDetector`,
    `NewFakeVulnDetectorWithAdvisories`, `InitFakeVulnDetector`,
    `InitFakeVulnDetectorWithAdvisories`)**: Test double for
    `module.VulnDetector` with mutex-guarded call counting whose
    `Detect(ctx, service)` method increments `CountCalls()` and delegates to a
    `FakeDetectFn` callback, and `Advisories()` returns configured advisories.
    `InitFakeVulnDetector(name, err, override)` and
    `InitFakeVulnDetectorWithAdvisories(name, err, advisories, override)` return
    a `module.InitVulnDetectorFn` that yields `err` when non-nil or constructs
    the fake.
-   **`FakeDetectFn`, `FakeDetectFnNoFindings`, `FakeDetectFnErrors`,
    `ErrFakeDetectGeneric`**: Callback type `func(ctx context.Context, svc
    *nspb.NetworkService) (*dpb.DetectionReportList, error)` and canned helpers
    for `FakeVulnDetector`. `FakeDetectFnNoFindings` returns `(nil, nil)`, while
    `FakeDetectFnErrors` returns `(nil, ErrFakeDetectGeneric)`.

## Usage

```go
import (
  "context"

  "github.com/google/goonami-scanner/common/testfakes/fakemodule"
  "github.com/google/goonami-scanner/core/module"

  dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

// Construct fakes directly with canned or custom callbacks.
fp := fakemodule.NewFakeFingerprinter(
    "fp1", fakemodule.FakeFingerprintFnDoNothing)
det := fakemodule.NewFakeVulnDetector("det1",
    func(ctx context.Context, svc *nspb.NetworkService) (
        *dpb.DetectionReportList, error,
    ) {
      return dpb.DetectionReportList_builder{}.Build(), nil
    })
_, err := det.Detect(ctx, svc)
calls := det.CountCalls() // 1

// Register module initializers (pass non-nil err to simulate init failure).
module.RegisterPortScanner("ps1", fakemodule.InitFakePortScanner(
    "ps1", nil, fakemodule.FakePortScanFnDoNothing))
```
