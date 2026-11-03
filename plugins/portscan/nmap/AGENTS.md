# Package `nmap`

Package `nmap` implements Goonami's Nmap-backed port-scanning plugin
(`module.PortScanner`), registered under the module name `"ps/nmap"`. It
executes Nmap against a single target via the shared Nmap client and translates
the resulting XML report into a Tsunami `*rpb.PortScanningReport`. During
translation, it extracts target endpoint metadata (`IP`, `HOSTNAME`, or
`IP_HOSTNAME`) along with open `TCP`, `UDP`, and `SCTP` services, software
versions, CPEs, and supported HTTP methods and SSL/TLS versions from Nmap script
output.

## Services

-   **Self-Registration (`"ps/nmap"`)**: Importing the package registers `New`
    under `"ps/nmap"` on `module.DefaultRegistry` via
    `module.RegisterPortScanner`.
-   **`Module` / `New`**: `Module` embeds `*module.BaseModule` and implements
    `module.PortScanner` over an underlying Nmap client. `New(ctx, config)`
    initializes and returns a `module.PortScanner` named `"ps/nmap"` configured
    from `*config.Config`.
-   **`(*Module).Scan`**: Runs Nmap against a single `target` and parses open
    `tcp`, `udp`, and `sctp` ports into a `*rpb.PortScanningReport` with
    endpoint details, service names (defaulting to `"unknown"`), CPEs, software
    versions, and `http-methods` / `ssl-enum-ciphers` NSE script output. Returns
    `(nil, nil)` when the host status is not `"up"`, and skips non-open ports or
    unrecognized transport protocols.
-   **`ErrNoOutput`, `ErrInvalidHostsCount`, `ErrInvalidAddressType`,
    `ErrNoAddressOrHostname`**: Sentinel errors returned by `Scan` when the Nmap
    XML output is `nil`, contains zero or multiple hosts instead of one,
    specifies an address type other than `"ipv4"` or `"ipv6"`, or lacks both an
    IP address and a hostname.

## Usage

Blank-import the package to register `"ps/nmap"` and resolve it via
`module.GetPortScanner`:

```go
import (
  "context"

  "google.golang.org/protobuf/proto"
  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/core/module"

  _ "github.com/google/goonami-scanner/plugins/portscan/nmap"

  cpb "github.com/google/goonami-scanner/core/config/config_go_proto"
  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func scanViaRegistry(
    ctx context.Context, target string,
) (*rpb.PortScanningReport, error) {
  cfg := config.FromProto(cpb.Config_builder{
    Workflowcfg: cpb.WorkflowConfiguration_builder{
      Portscan: proto.String("ps/nmap"),
    }.Build(),
  }.Build())

  scanner, err := module.GetPortScanner(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```

Instantiate and invoke the `"ps/nmap"` scanner directly:

```go
import (
  "context"

  "github.com/google/goonami-scanner/core/config"
  "github.com/google/goonami-scanner/plugins/portscan/nmap"

  rpb "github.com/google/tsunami-security-scanner/proto/go/reconnaissance_go_proto"
)

func scanDirect(
    ctx context.Context, cfg *config.Config, target string,
) (*rpb.PortScanningReport, error) {
  scanner, err := nmap.New(ctx, cfg)
  if err != nil {
    return nil, err
  }
  return scanner.Scan(ctx, target)
}
```
