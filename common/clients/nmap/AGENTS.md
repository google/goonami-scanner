# Package `nmap`

Package `nmap` wraps the external `nmap` network scanner binary and parses its
XML (`-oX`) output into typed Go structures. It translates Goonami client and
global configuration settings—covering scan technique, packet rate limits,
timing intensity, IPv6 targeting, port selection, host discovery, service
version detection, and NSE scripts—into command-line arguments and enforces
execution timeouts. Reconnaissance plugins such as the `ps/nmap` port scanner
use `Client` to run port and service discovery scans, while test doubles such as
`fakenmap` use `Client` and `ParseXMLOutput` to replay canned XML scan reports.

## Services

-   **`Client`**: Interface exposing
    `Run(ctx context.Context, target string) (*OutputXML, error)` for executing
    an `nmap` scan against a single target and returning the parsed XML report,
    allowing callers to substitute fakes in unit tests.
-   **`SimpleClient` / `New`**: Concrete `Client` initialized via
    `New(cfg *config.Config)`, reading `cfg.ClientsConfig().GetNmap()` when
    present or falling back to an empty `NmapClientConfig` alongside global
    settings from `cfg.GlobalConfig()`.
-   **`(*SimpleClient).Run`**: Executes the configured `nmap` binary (defaulting
    to `"nmap"` on `PATH`) with XML output written to a temporary file
    (`nmap-*.xml`) that is automatically removed on return, then parses the file
    via `ParseXMLOutput`. When `timeout_seconds > 0`, it wraps `ctx` with
    `context.WithTimeout` and joins any context deadline or cancellation error
    with `ErrNmapExecution`.
-   **`(*SimpleClient).CommandLine`**: Returns the `nmap` CLI argument slice
    built for `target` (with an empty `-oX` path), mapping `scan_technique`
    (`-sT` or `-sU`), packet rates (`--min-rate` and global `--max-rate`),
    timing (`-T1`–`-T5`, defaulting out-of-range values to `-T3`), IPv6 (`-6`),
    target ports (`-p<list>` or `-p-`), and `-Pn` when host discovery is
    disabled. It also appends `-sV` with optional `--version-intensity`
    (clamping values above `9` to `5`), global `http.useragent` `--script-args`,
    and NSE `--script` flags for `http-methods`, `ssl-cert`, and
    `ssl-enum-ciphers`.
-   **`ParseXMLOutput`**: Unmarshals raw `nmap` `-oX` XML bytes into an
    `*OutputXML` structure, returning an error wrapping `ErrNmapXMLUnmarshal` on
    malformed XML.
-   **`OutputXML` & Run Metadata (`Verbose`, `Debugging`, `Runstats`,
    `Finished`)**: Represent the root `<nmaprun>` XML document (`OutputXML`),
    capturing invocation metadata (`Args`, `StartStr`, `Version`), verbosity and
    debug levels, pre/post-scan `Script` slices, scanned `Hosts`, and completion
    statistics.
-   **Host, Port, Service & OS Output Types (`Host`, `Status`, `Address`,
    `Hostnames`, `Hostname`, `Ports`, `ExtraPorts`, `ExtraReasons`, `Port`,
    `State`, `Service`, `Script`, `Table`, `Elem`, `HostScript`, `OS`,
    `PortUsed`, `OSMatch`, `OSFingerprint`, `Distance`, `Uptime`, `TCPSequence`,
    `IPIDSequence`, `Trace`, `Hop`, `Smurf`)**: Model per-host scan findings in
    `<host>` elements, including IPv4/IPv6 addresses, hostnames, port states,
    detected `Service` metadata (`Name`, `Product`, `Version`, `ExtraInfo`,
    `Tunnel`, `CPE`), structured NSE `Script` `Table`/`Elem` results, OS
    fingerprinting, and traceroute/sequence details.
-   **Configuration Proto (`nmap_client_config_go_proto`)**: Defines
    `goonami.proto.configs.clients.NmapClientConfig` and its `Technique` enum
    (`UNKNOWN`, `CONNECT`, `UDP`), configuring `binary_path`, `timeout_seconds`
    (default `300`), `scan_technique` (default `CONNECT`), `scan_intensity`
    (default `3`), `enable_host_discovery`, `min_rate`,
    `enable_version_detection`, `version_intensity`,
    `enable_http_methods_detection`, and `enable_ssl_detection`.
-   **Sentinel Errors**: Exports `ErrInvalidTechnique` for unsupported
    `scan_technique` enum values, `ErrNmapTempFile` for temporary XML file setup
    failures, `ErrNmapExecution` for `nmap` subprocess execution or timeout
    failures, `ErrNmapOutputRead` for output file read errors, and
    `ErrNmapXMLUnmarshal` for XML parsing failures.

## Usage

Run a configured `nmap` scan against a target and collect open port numbers:

```go
import (
    "context"

    "github.com/google/goonami-scanner/common/clients/nmap"
    "github.com/google/goonami-scanner/core/config"
)

func scanOpenPorts(
    ctx context.Context, cfg *config.Config, target string,
) ([]int, error) {
    client := nmap.New(cfg)
    result, err := client.Run(ctx, target)
    if err != nil {
        return nil, err
    }

    var openPorts []int
    for _, host := range result.Hosts {
        for _, port := range host.Ports.Ports {
            if port.State.State == "open" {
                openPorts = append(openPorts, port.PortID)
            }
        }
    }
    return openPorts, nil
}
```

Parse standalone `nmap` XML output from disk (for example, when loading saved
scan reports or test fixtures):

```go
import (
    "os"

    "github.com/google/goonami-scanner/common/clients/nmap"
)

func loadScanReport(xmlPath string) (*nmap.OutputXML, error) {
    data, err := os.ReadFile(xmlPath)
    if err != nil {
        return nil, err
    }
    return nmap.ParseXMLOutput(data)
}
```
