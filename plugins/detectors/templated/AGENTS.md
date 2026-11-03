# Package `templated`

Package `templated` embeds Goonami's textproto-defined vulnerability detection
plugins (`detections/**/*.textproto`) and self-registers them with the global
`module` detector registry at package initialization. Each enabled
`TemplatedPlugin` definition is registered under the `"dt/tpl/<PluginName>"`
naming prefix and instantiated on demand via `templatedengine.New`. Scanner
binaries blank-import this package so its bundled CVE and exposed-UI detectors
can be selected and filtered through workflow configuration.

## Services

-   **`init` (Detector Self-Registration)**: Loads all enabled `.textproto`
    `TemplatedPlugin` definitions from the embedded `detections/` filesystem via
    `templatedengine.LoadPluginsFromFS`, panicking if loading fails. Registers
    each plugin with `module.RegisterDetector` under
    `"dt/tpl/" + proto.GetInfo().GetName()` using a constructor backed by
    `templatedengine.New`.
-   **`Loader` (`NewLoader`)**: Holds a `*config.Config` reference constructed
    via `NewLoader(cfg)`. It currently exposes no fields or methods, as detector
    registration occurs automatically during package initialization.
-   **`detections/` Catalog & Test Suite**: Non-test `.textproto` files under
    `detections/` define `TemplatedPlugin` workflows embedded via
    `//go:embed detections`, while companion `*_test.textproto` files define
    `TemplatedPluginTests` suites. Package tests automatically load all embedded
    plugin and test definitions via `faketemplated.LoadPluginsAndTests` and run
    each test case against mock HTTP and callback servers.

## Usage

Blank-import `templated` to register all bundled `"dt/tpl/..."` detectors and
resolve them through workflow configuration filters:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"
  _ "github.com/google/goonami-scanner/plugins/detectors/templated"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
)

func loadDetectors(ctx context.Context) ([]module.VulnDetector, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Workflowcfg: cpb.WorkflowConfiguration_builder{
          Detectors: cpb.WorkflowConfiguration_ModuleFilter_builder{
              Require: []string{"dt/tpl/.*"},
          }.Build(),
      }.Build(),
  }.Build())

  return module.GetDetectors(ctx, cfg)
}
```
