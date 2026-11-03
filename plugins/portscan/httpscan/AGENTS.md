# Package `httpscan`

Package `httpscan` implements a `module.PortScanner` plugin (`"ps/httpscan"`)
that discovers open network ports using HTTP `GET` requests, enabling port
scanning through HTTP proxies or restricted networks. Importing the package for
side effects self-registers its constructor on `module.DefaultRegistry` under
`"ps/httpscan"`. During a scan, it probes configured ports concurrently via
Goonami's shared HTTP client and reports ports responding with HTTP status codes
outside `invalid_exit_codes` as open network services.

## Services

-   **`Module` (`New`, `Name`)**: Concrete port scanner embedding
    `*module.BaseModule` (`Name()` returns `"ps/httpscan"`) and registered on
    `module.DefaultRegistry` via `init()`. `New(ctx, cfg)` initializes a
    `module.PortScanner` using `cfg.GlobalConfig().GetPortsToScan()` (defaulting
    to ports `1`–`65535` when unset) and `cfg.PluginsConfig().GetHttpscan()`
    (warning and falling back to `DefaultConfig()` when absent).
-   **`(*Module).Scan`**: `Scan(ctx, target)` parses `target` into a
    `*npb.NetworkEndpoint` (`IP`, `HOSTNAME`, or `IP_HOSTNAME`) and probes
    configured ports concurrently up to `max_concurrency` via HTTP `GET`
    requests on `http.SharedClient`. Transport errors and status codes in
    `invalid_exit_codes` are treated as closed ports, while other responses
    append an open `*nspb.NetworkService` (with `SupportedHttpMethods: ["GET"]`)
    to the returned `*rpb.PortScanningReport`.
-   **`DefaultConfig`**: Returns a default `*hcpb.HttpScanPluginConfig` with
    `InvalidExitCodes` set to `[400, 502]`. Providing an explicit configuration
    tailored to the target environment or HTTP proxy is recommended over relying
    on these defaults.
-   **`HttpScanPluginConfig` (`httpscan_portscan_config_go_proto`)**: Protobuf
    configuration message
    (`goonami.proto.configs.portscan.HttpScanPluginConfig`) defining
    `invalid_exit_codes`, the HTTP status codes that signal a scanned port is
    closed.

## Usage

Register `"ps/httpscan"` via side-effect import and resolve it through
`module.GetPortScanner`:

```go
import (
  "context"

  "google.golang.org/protobuf/proto"
  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  _ "github.com/google/goonami-scanner/plugins/portscan/httpscan"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
  hcpb "github.com/google/goonami-scanner/plugins/portscan/httpscan/httpscan_portscan_config_go_proto"
  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func scanTarget(
    ctx context.Context, target string,
) (*rpb.PortScanningReport, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Globalcfg: cpb.GlobalConfig_builder{
          PortsToScan: []uint32{80, 443, 8080},
          Performance: cpb.GlobalConfig_Performance_builder{
              TimeoutPerRequestSeconds: proto.Int32(5),
              MaxConcurrency:           proto.Int32(10),
          }.Build(),
      }.Build(),
      Plugins: cpb.PluginsConfig_builder{
          Httpscan: hcpb.HttpScanPluginConfig_builder{
              InvalidExitCodes: []int32{400, 502, 504},
          }.Build(),
      }.Build(),
      Workflowcfg: cpb.WorkflowConfiguration_builder{
          Portscan: proto.String("ps/httpscan"),
      }.Build(),
  }.Build())

  scanner, err := module.GetPortScanner(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```

Instantiate the scanner directly with `httpscan.New`:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
  "github.com/google/goonami-scanner/plugins/portscan/httpscan"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func scanWithDefaults(
    ctx context.Context, target string,
) (*rpb.PortScanningReport, error) {
  cfg := config.FromProto(cpb.Config_builder{
      Globalcfg: cpb.GlobalConfig_builder{
          PortsToScan: []uint32{80, 443},
      }.Build(),
      Plugins: cpb.PluginsConfig_builder{
          Httpscan: httpscan.DefaultConfig(),
      }.Build(),
  }.Build())

  scanner, err := httpscan.New(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```
