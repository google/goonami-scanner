# Package `entrypoint`

Package `entrypoint` provides the primary library entry point for initializing
and running Goonami vulnerability scans. It wires a loaded `config.Config`,
optional global logging and metrics recording, shared HTTP and callback server
clients, and registered scan plugins onto a `runner.Runner`. Callers register
desired HTTP clients and scan modules (port scanners, fingerprinters, and
detectors) in their global registries—typically via blank imports—before
constructing and running an `Entrypoint`.

## Services

-   **`Options`**: Configures engine initialization with a required `Config`
    (`*config.Config`) and optional `Runner` (`runner.Runner`), `Logger`
    (`log.Logger`), and `Recorder` (`metrics.Recorder`, discarding metrics when
    unset).
-   **`Entrypoint`**: Represents an initialized Goonami scanner bound to a
    loaded configuration and scan runner.
-   **`New(ctx, options)`**: Validates `Options`, creates a default
    `simplerunner` when `Options.Runner` is nil, initializes the shared HTTP and
    callback server clients, and registers configured port scanner,
    fingerprinter, and detector modules onto the runner. Creating an
    `Entrypoint` mutates process-wide state when installing `Options.Logger` or
    `Options.Recorder` and initializing global client singletons.
-   **`(*Entrypoint).Run(ctx, target)`**: Executes the scan workflow against
    `target` via the underlying `runner.Runner` and returns the Tsunami
    `*srpb.ScanResults` report.
-   **`(*Entrypoint).Artifacts()`**: Returns the filesystem path to the
    directory where scan artifacts are stored (`Config.ArtifactsDirectory()`).
-   **`Advisories(ctx, logger)`**: Initializes all registered vulnerability
    detectors using default configuration and returns the combined list of
    supported advisories (`*vulnpb.VulnerabilityList`), optionally installing
    `logger` before module initialization.

## Usage

```go
package example

import (
    "context"

    "github.com/google/goonami-scanner/core/config"
    "github.com/google/goonami-scanner/core/entrypoint"
    "github.com/google/goonami-scanner/core/metrics"

    // Register HTTP client and scan plugins before calling entrypoint.New.
    _ "github.com/google/goonami-scanner/core/net/http/simpleclient"
    _ "github.com/google/goonami-scanner/plugins/detectors/templated"
    _ "github.com/google/goonami-scanner/plugins/portscan/nmap"

    srpb "github.com/google/tsunami-security-scanner/proto/go/scan_results_go_proto"
)

func runScan(
    ctx context.Context, cfgPath, outDir, target string,
) (*srpb.ScanResults, error) {
    cfg, err := config.FromFile(cfgPath)
    if err != nil {
        return nil, err
    }
    if err := cfg.CreateDirectories(outDir); err != nil {
        return nil, err
    }
    defer cfg.Close(ctx)

    scanner, err := entrypoint.New(ctx, &entrypoint.Options{
        Config:   cfg,
        Recorder: metrics.NewCollector(),
    })
    if err != nil {
        return nil, err
    }
    return scanner.Run(ctx, target)
}
```
