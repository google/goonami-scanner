# Package `noop`

Package `noop` implements the `"ps/noop"` port scanner plugin
(`module.PortScanner`), which reports all configured ports as open without
sending network probes. It is intended for workflows where open ports on a
target have already been discovered externally and provided via
`globalcfg.ports_to_scan`. Importing the package registers `New` under
`"ps/noop"` in `module.DefaultRegistry`.

## Services

-   **`"ps/noop"` Registration**: Package `init()` calls
    `module.RegisterPortScanner("ps/noop", New)` so blank-importing the package
    registers the scanner in `module.DefaultRegistry`.
-   **`Module`**: Concrete port scanner struct embedding `*module.BaseModule`
    (`Name()` returns `"ps/noop"`) that implements `module.PortScanner`.
-   **`New`**: Constructor
    (`func(context.Context, *config.Config) (module.PortScanner, error)`) that
    reads `config.GlobalConfig().GetPortsToScan()` and returns an initialized
    `*Module`. Returns `ErrNoPortsToScan` if the configured port list is empty.
-   **`(*Module).Scan`**: Parses `target` via `netendpoint.FromString` and
    returns a `*rpb.PortScanningReport` marking every configured port as open
    without performing network I/O. Emits each port as a `*nspb.NetworkService`
    with endpoint type `IP_PORT` or `HOSTNAME_PORT` matching the parsed target.
-   **`ErrNoPortsToScan`**: Sentinel error returned by `New` when
    `globalcfg.ports_to_scan` is empty, preventing all 65,535 ports from being
    treated as open.

## Usage

Blank-import `noop` to register `"ps/noop"` and resolve it through
`module.GetPortScanner`:

```go
import (
  "context"

  "google.golang.org/protobuf/proto"
  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"

  _ "github.com/google/goonami-scanner/plugins/portscan/noop"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func scanKnownPorts(
    ctx context.Context, target string, ports []uint32,
) (*rpb.PortScanningReport, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Workflowcfg: cpb.WorkflowConfiguration_builder{
          Portscan: proto.String("ps/noop"),
      }.Build(),
      Globalcfg: cpb.GlobalConfig_builder{
          PortsToScan: ports,
      }.Build(),
  }.Build())

  scanner, err := module.GetPortScanner(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```

Construct the scanner directly via `noop.New`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/plugins/portscan/noop"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func directNoopScan(
    ctx context.Context, target string,
) (*rpb.PortScanningReport, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Globalcfg: cpb.GlobalConfig_builder{
          PortsToScan: []uint32{80, 443},
      }.Build(),
  }.Build())

  scanner, err := noop.New(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```
