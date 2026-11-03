# Package `module`

Package `module` defines the core plugin interfaces (`Module`, `PortScanner`,
`Fingerprinter`, and `VulnDetector`), the embeddable `BaseModule` helper, and
the module registry for Goonami's scanning pipeline. Plugin implementations
embed `*BaseModule` (or `BaseModule`), implement one of the stage-specific
interfaces, and register their `Init*Fn` constructors with a `Registry` or the
global `DefaultRegistry`. At runtime, the engine queries the registry with a
`*config.Config` to select, filter via full-string regular expressions, and
initialize the configured port scanner, fingerprinters, and vulnerability
detectors.

## Services

-   **`Module` / `BaseModule` (`NewBaseModule`, `Name`)**: `Module` is the base
    interface (`Name() string`) satisfied by every Goonami plugin. `BaseModule`
    (constructed via `NewBaseModule(name)`) provides the standard embeddable
    `Name()` implementation for concrete modules.
-   **`PortScanner` / `InitPortScannerFn`**: Interface for port-scanning modules
    exposing `Name()` and `Scan(ctx, target) (*rpb.PortScanningReport, error)`
    to discover open network services on a target. `InitPortScannerFn`
    (`func(context.Context, *config.Config) (PortScanner, error)`) is the
    constructor callback signature accepted by the registry.
-   **`Fingerprinter` / `InitFingerprinterFn`**: Interface for
    service-enrichment modules exposing `Name()` and
    `Fingerprint(ctx, service) ([]*nspb.NetworkService, error)`, returning a
    slice so a single `*nspb.NetworkService` can split into multiple identified
    software entries. `InitFingerprinterFn`
    (`func(context.Context, *config.Config) (Fingerprinter, error)`) is the
    constructor callback signature accepted by the registry.
-   **`VulnDetector` / `InitVulnDetectorFn`**: Interface for vulnerability
    detection modules exposing `Name()` and
    `Detect(ctx, service) (*dpb.DetectionReportList, error)` against a target
    `*nspb.NetworkService`. `InitVulnDetectorFn`
    (`func(context.Context, *config.Config) (VulnDetector, error)`) is the
    constructor callback signature accepted by the registry.
-   **`Registry` (`NewRegistry`, `Clear`), `DefaultRegistry`, `ClearRegistry`**:
    Concurrency-safe container (`NewRegistry()`) that stores port scanner,
    fingerprinter, and detector initializers in registration order and resets
    all entries via `Clear()`. `DefaultRegistry` is the global `*Registry` used
    by self-registering packages, and `ClearRegistry()` clears `DefaultRegistry`
    for test isolation.
-   **`(*Registry).RegisterPortScanner` / `RegisterFingerprinter` /
    `RegisterDetector` & `RegisterPortScanner` / `RegisterFingerprinter` /
    `RegisterDetector`**: Register a module name and its `Init*Fn` constructor
    on a `*Registry` or on `DefaultRegistry`. Registering a duplicate name
    within the same module category panics.
-   **`(*Registry).GetPortScanner` / `GetPortScanner`**: Reads
    `cfg.WorkflowConfig().GetPortscan()`, looks up the matching
    `InitPortScannerFn` on the `*Registry` or `DefaultRegistry`, and returns the
    initialized `PortScanner`. Returns an error if no port scanner is
    configured, the name is not registered, or the initializer fails.
-   **`(*Registry).GetFingerprinters` / `GetDetectors` & `GetFingerprinters` /
    `GetDetectors`**: Resolve and initialize the fingerprinters or detectors
    selected by `cfg.WorkflowConfig()`, returning `(nil, nil)` if the
    corresponding workflow filter section is nil. Resolution matches `require`
    and `ignore` patterns as full-string regular expressions (`^` to `$`),
    deduplicating matches in `require` and registration order while returning an
    error on invalid regexes, unmatched `require` patterns, or initializer
    failures.

## Usage

Implement and self-register a `VulnDetector` embedding `*module.BaseModule`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"

  dpb "github.com/google/tsunami-security-scanner/proto/go/detection_go_proto"
  nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

type customDetector struct {
  *module.BaseModule
}

func NewDetector(
    ctx context.Context, cfg *config.Config,
) (module.VulnDetector, error) {
  return &customDetector{
      BaseModule: module.NewBaseModule("dt/custom"),
  }, nil
}

func (d *customDetector) Detect(
    ctx context.Context, service *nspb.NetworkService,
) (*dpb.DetectionReportList, error) {
  return dpb.DetectionReportList_builder{}.Build(), nil
}

func init() {
  module.RegisterDetector("dt/custom", NewDetector)
}
```

Resolve and initialize configured modules from a `Registry` using workflow
filters:

```go
import (
  "context"

  "google.golang.org/protobuf/proto"
  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func loadModules(
    ctx context.Context, reg *module.Registry,
) (module.PortScanner, []module.VulnDetector, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Workflowcfg: cpb.WorkflowConfiguration_builder{
          Portscan: proto.String("nmap"),
          Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
              Require: []string{"dt/.*"},
              Ignore:  []string{"dt/experimental"},
          }.Build(),
      }.Build(),
  }.Build())

  scanner, err := reg.GetPortScanner(ctx, cfg)
  if err != nil {
    return nil, nil, err
  }
  detectors, err := reg.GetDetectors(ctx, cfg)
  if err != nil {
    return nil, nil, err
  }
  return scanner, detectors, nil
}
```
